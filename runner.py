"""
Noderouter Python Runner — Tunnel Architecture
==============================================
Pure asyncio daemon. Establishes an outbound gRPC bidi-stream tunnel to Go
Core (mutual TLS) and processes tasks over it:

  Sync Channel  →  Request/Response frames over the gRPC Tunnel stream  (< 5 s tasks)
  Async Channel →  PostgreSQL asyncpg LISTEN new_job + SKIP LOCKED claim
                   (long-running tasks; executed in isolated ProcessPoolExecutor)

Transport security (self-managed, fully in-memory mTLS):
  On every (re)connect the runner generates an ECDSA keypair in memory, sends
  an HMAC-signed CSR to Core's plaintext Enroll RPC, and receives a client
  cert + CA bundle issued by Core's ephemeral per-boot CA. The Tunnel stream
  then runs over mTLS; nothing is ever written to disk. Core restarts rotate
  the CA, which the per-connect re-enrollment makes self-healing.

Hot-reload triggered by PostgreSQL NOTIFY app_updated via asyncpg LISTEN.
No HTTP server is exposed — runners dial Core outbound; Core sends frames inward.
"""

import asyncio
import concurrent.futures
import contextlib
from datetime import datetime, timezone
import hashlib
import hmac as hmac_lib
import importlib.machinery
import importlib.util
import inspect
import io
import json
import logging
import multiprocessing
import os
import platform
import re
import shutil
import signal
import sys
import threading
import time
import tempfile
import uuid
import zipfile

import asyncpg
import grpc
import grpc.aio
import psycopg2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from dotenv import load_dotenv

import tunnel_pb2
import tunnel_pb2_grpc

# ── Bootstrap ─────────────────────────────────────────────────────────────────
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [runner] %(levelname)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────────
# CORE_GRPC_TARGET   — host:port of Core's mTLS Tunnel listener
#                      (direct: noderouter-core:50051 / via NGINX stream: domain:8443)
# CORE_ENROLL_TARGET — host:port of Core's plaintext Enroll listener
#                      (direct: noderouter-core:50052 / via NGINX stream: domain:8444)
CORE_GRPC_TARGET = os.getenv("CORE_GRPC_TARGET", "").strip() or "localhost:50051"


def _default_enroll_target() -> str:
    """Same host as the tunnel target, default enroll port 50052."""
    host = CORE_GRPC_TARGET.rsplit(":", 1)[0] if ":" in CORE_GRPC_TARGET else CORE_GRPC_TARGET
    return f"{host}:50052"


CORE_ENROLL_TARGET = os.getenv("CORE_ENROLL_TARGET", "").strip() or _default_enroll_target()

NODE_ID           = os.getenv("NODE_ID", "")
RUNNER_SECRET     = os.getenv("RUNNER_SECRET", "")
APPS_DIR          = os.getenv(
    "APPS_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "apps"),
)
DATABASE_URL      = os.getenv("DATABASE_URL", "")
ASYNC_MAX_WORKERS = int(os.getenv("ASYNC_MAX_WORKERS", "4"))
SYNC_MAX_WORKERS  = int(os.getenv("SYNC_MAX_WORKERS", "8"))

# In-memory mTLS credentials — populated by _enroll() on each (re)connect.
_client_cert_pem: bytes = b""
_client_key_pem:  bytes = b""
_ca_cert_pem:     bytes = b""
_server_name:     str   = ""

_IS_WINDOWS = platform.system() == "Windows"

# ── Shutdown Coordination ──────────────────────────────────────────────────────
# Declared here; initialised as asyncio.Event() inside main().
_shutdown_event: asyncio.Event

# ── Worker Pools ───────────────────────────────────────────────────────────────
# Initialised in __main__ guard to avoid Windows spawn recursion.
_process_pool: concurrent.futures.ProcessPoolExecutor | None = None
_thread_pool:  concurrent.futures.ThreadPoolExecutor  | None = None

# ── DB Pool (asyncpg) ─────────────────────────────────────────────────────────
# The runner keeps a Postgres pool for its OWN control-plane work (job claim,
# status updates, app blob fetch, LISTEN/NOTIFY). Apps NEVER touch Postgres
# directly — all app SQL flows through registered named queries over the tunnel
# (see the Named Query Client section). DATABASE_URL is stripped from app
# subprocesses so app code cannot open its own connection.
_db_pool: asyncpg.Pool | None = None

# ── App Registry ───────────────────────────────────────────────────────────────
_app_registry: dict = {}
_registry_lock = threading.Lock()   # sync lock — held only during writes in _load_app
_import_lock = threading.Lock()      # serialises app module imports in the daemon process
_exec_params: dict[int, set] = {}    # id(module) → execute() parameter names
_app_versions: dict[str, str] = {}   # app_name → manifest version (sent in QueryRequest)
# app_name → {action_name → ordered param names}, parsed from manifest.json's
# "actions". Lets the named-query client reorder a dict of params into the
# positional $1..$N list Core binds to the action's SQL (see _map_query_params).
_app_query_params: dict[str, dict[str, list[str]]] = {}

# ── Named Query Client (apps → Core over the tunnel) ──────────────────────────
# QUERY_TIMEOUT bounds a single named-query round-trip. Set below the Core
# Send timeout so a hung query surfaces as an app error, not a tunnel stall.
QUERY_TIMEOUT = 30.0
_event_loop: asyncio.AbstractEventLoop | None = None   # set in main()
_tunnel_outq: asyncio.Queue | None = None              # live tunnel outbound queue
_query_pending: dict[str, asyncio.Future] = {}         # qid → Future((status, rows, error))

# ── Subprocess → parent query bridge (async-job ProcessPoolExecutor workers) ──
# Subprocess workers cannot reach the event loop / tunnel, so query() and
# report_progress() marshal requests to the parent over Manager queues. The
# parent's _bridge_drain_loop forwards them to the tunnel / job table.
_bridge_req_q = None          # Manager Queue: workers → parent  (kind, idx, payload)
_bridge_resp_qs = None        # list[Manager Queue]: parent → worker[idx]
_bridge_idx = None            # Manager Value('i'): hands out worker slot indices
_bridge_idx_lock = None       # Manager Lock guarding _bridge_idx
# Worker-local (set by _worker_init in each subprocess):
_W_REQ_Q = None
_W_RESP_Q = None
_W_IDX = 0

# ── Per-app module namespaces (F1/F2) ──────────────────────────────────────────
# Each app loads under a unique synthetic package (see _import_app_module), so
# sibling modules of different apps can never collide in sys.modules, and a
# redeploy purges exactly the modules the old version registered.
_app_active_pkg: dict[str, str] = {}          # app_name → current package name
_path_refs: dict[str, int] = {}               # sys.path entry → in-flight user count
_path_refs_lock = threading.Lock()

# ── Sync concurrency control (B9, B12) ────────────────────────────────────────
# asyncio objects must be created inside main() after the event loop is running.
_sync_semaphore: asyncio.Semaphore | None = None  # B9: bounds concurrent _handle_req tasks
_app_load_locks: dict[str, asyncio.Lock] = {}     # B12: per-app load coalescing
_app_load_locks_mu: asyncio.Lock | None = None    # guards _app_load_locks dict


# ── Backoff ────────────────────────────────────────────────────────────────────
def _backoff(attempt: int, base: float = 1.0, cap: float = 60.0) -> float:
    """Exponential backoff with ±25 % jitter, capped at `cap` seconds."""
    import random
    delay = min(base * (2 ** attempt), cap)
    return delay * (0.75 + random.random() * 0.5)


# ── App Name Validation ────────────────────────────────────────────────────────
_APP_NAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$')


def _validate_app_name(app_name: str) -> str | None:
    """Return an error string if app_name is unsafe, None if valid."""
    if not _APP_NAME_RE.match(app_name):
        return (
            f"invalid app name '{app_name}': must start with alphanumeric "
            "and contain only [a-zA-Z0-9_-] (max 128 chars)"
        )
    return None


def _resolve_app_path(app_name: str) -> str | None:
    """Return the absolute path to an app's entry point, or None if not found."""
    candidates = [
        os.path.join(APPS_DIR, app_name, "main.py"),
        os.path.join(APPS_DIR, f"{app_name}.py"),
    ]
    return next((p for p in candidates if os.path.isfile(p)), None)


@contextlib.contextmanager
def _app_import_context(app_path: str):
    """
    Make an app's directory and optional libs/ directory importable while the
    block runs — both during module load and across execute(), so lazy imports
    inside app code resolve (F3).

    Entries are reference-counted: overlapping executions of different apps —
    or of the same app on several threads — each pin the paths they need, and
    a path leaves sys.path only when its last user exits. The lock guards the
    bookkeeping only and is never held across user code.
    """
    app_dir = os.path.realpath(os.path.dirname(app_path))
    libs_dir = os.path.join(app_dir, "libs")
    import_paths = []
    if os.path.isdir(libs_dir):
        import_paths.append(libs_dir)
    if app_dir not in import_paths:
        import_paths.append(app_dir)

    with _path_refs_lock:
        # Reversed so import_paths[0] (libs/) lands first on sys.path.
        for path in reversed(import_paths):
            if _path_refs.get(path, 0) == 0 and path not in sys.path:
                sys.path.insert(0, path)
            _path_refs[path] = _path_refs.get(path, 0) + 1
    try:
        yield
    finally:
        with _path_refs_lock:
            for path in import_paths:
                remaining = _path_refs.get(path, 1) - 1
                if remaining > 0:
                    _path_refs[path] = remaining
                else:
                    _path_refs.pop(path, None)
                    with contextlib.suppress(ValueError):
                        sys.path.remove(path)


# ── Node ID resolution ─────────────────────────────────────────────────────────
def _node_id_file() -> str:
    """
    Return the per-hostname .node_id file path inside APPS_DIR.

    Keyed by hostname so multiple runners sharing the same APPS_DIR volume
    (e.g. two containers on the same Docker host) each persist their own
    node_id without overwriting each other's file.
    """
    import socket
    hostname = os.getenv("HOSTNAME", socket.gethostname())
    safe     = re.sub(r"[^a-zA-Z0-9_-]", "_", hostname)[:64]
    return os.path.join(APPS_DIR, f".node_id_{safe}")


def _clear_persisted_node_id() -> None:
    """
    Reset the module-level NODE_ID and delete the persisted .node_id file.

    Called by _tunnel_loop when Core returns 401/403 — indicates the node
    record was removed or the DB was wiped. Clearing the file forces the
    next _enroll() call to register fresh rather than replaying
    a UUID that no longer exists in Core's database.
    """
    global NODE_ID
    NODE_ID = ""
    node_id_file = _node_id_file()
    try:
        os.remove(node_id_file)
        log.info("[node-id] Cleared persisted node_id file: %s", node_id_file)
    except FileNotFoundError:
        pass
    except OSError as exc:
        log.warning("[node-id] Could not remove node_id file %s: %s", node_id_file, exc)


def _detect_location() -> str:
    """
    Auto-detect the deployment environment and return the matching location_type.

    Returns one of two values:
      "docker_internal" — runner is inside a Docker container on the same host
                          as Core (/.dockerenv marker is present).
      "cloud"           — any other deployment: remote Docker on a cloud VM,
                          AWS ECS/EC2, GCP Cloud Run, Azure Container, Kubernetes,
                          or any bare-metal remote machine.

    Runners in this architecture are always containerised. The fallback for any
    non-Docker environment is "cloud" (not "localhost"). Override by setting the
    NODE_LOCATION env var to any valid location_type.

    The AWS IMDSv1 probe hits 169.254.169.254 (link-local, LAN-only) with a
    300 ms timeout — no packets leave the private network.
    """
    import urllib.request as _req

    # Operator override always wins.
    if override := os.getenv("NODE_LOCATION"):
        return override

    # Docker: standard marker created by the Docker daemon at container start.
    if os.path.exists("/.dockerenv"):
        return "docker_internal"

    # AWS EC2 / ECS — IMDSv1 link-local probe (LAN-only, no external traffic).
    try:
        _req.urlopen("http://169.254.169.254/latest/meta-data/instance-id", timeout=0.3)
        return "cloud"
    except Exception:
        pass

    # Azure — standard env vars set by App Service and Container Instances.
    if os.getenv("WEBSITE_INSTANCE_ID") or os.getenv("AZURE_REGION"):
        return "cloud"

    # GCP Cloud Run / Compute Engine.
    if os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("K_SERVICE"):
        return "cloud"

    # Generic Kubernetes (covers EKS, GKE, AKS, and bare-metal k8s).
    if os.getenv("KUBERNETES_SERVICE_HOST"):
        return "cloud"

    # Default: any non-Docker runner is a remote/cloud deployment.
    return "cloud"


def _enroll() -> None:
    """
    Generate an in-memory ECDSA P-256 keypair + CSR, send an HMAC-signed
    Enroll RPC to Core's plaintext listener, verify the response signature,
    and store the issued certs + node_id in module globals.

    Called via asyncio.to_thread at the start of every tunnel connect iteration
    so the runner always holds certs signed by Core's current ephemeral per-boot
    CA — making Core restarts self-healing without any manual intervention.

    Raises on failure; the tunnel loop retries with exponential backoff.
    """
    global NODE_ID, _client_cert_pem, _client_key_pem, _ca_cert_pem, _server_name
    import socket

    hostname   = os.getenv("HOSTNAME", socket.gethostname())
    location   = _detect_location()
    # runner_url is a stable per-machine identity — unique per container/host.
    # Core uses it to detect and delete ghost nodes from previous Docker recreates
    # (where the hostname changes but the physical machine is the same).
    runner_url = f"runner://{hostname}"

    # Restore previously-assigned NODE_ID from disk so Core can match the node row.
    if not NODE_ID:
        node_id_file = _node_id_file()
        if os.path.isfile(node_id_file):
            try:
                val = open(node_id_file).read().strip()  # noqa: WPS515
                if val:
                    NODE_ID = val
            except OSError:
                pass

    # Generate ephemeral ECDSA P-256 keypair entirely in memory.
    key = ec.generate_private_key(ec.SECP256R1())
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

    # Build a CSR signed by our ephemeral private key.
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ]))
        .sign(key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    # HMAC over "{ts}\n{name}\n{sha256hex(csr_pem)}" — mirrors VerifyHMACIdentity
    # in sorai-core/middleware/hmac.go.
    ts       = str(int(time.time()))
    csr_hash = hashlib.sha256(csr_pem).hexdigest()
    message  = f"{ts}\n{hostname}\n{csr_hash}"
    sig      = "sha256=" + hmac_lib.new(
        RUNNER_SECRET.encode(), message.encode(), hashlib.sha256,
    ).hexdigest()

    channel = grpc.insecure_channel(CORE_ENROLL_TARGET)
    try:
        stub     = tunnel_pb2_grpc.TunnelServiceStub(channel)
        metadata = [("x-noderouter-ts", ts), ("x-noderouter-sig", sig)]
        resp = stub.Enroll(
            tunnel_pb2.EnrollRequest(
                name=hostname,
                location_type=location,
                runner_url=runner_url,
                csr_pem=csr_pem,
            ),
            metadata=metadata,
            timeout=10,
        )
    finally:
        channel.close()

    # Verify the response integrity to detect MITM / wrong RUNNER_SECRET.
    cert_hash    = hashlib.sha256(resp.client_cert_pem).hexdigest()
    ca_hash      = hashlib.sha256(resp.ca_cert_pem).hexdigest()
    expected_msg = f"{resp.node_id}\n{cert_hash}\n{ca_hash}"
    expected_sig = "sha256=" + hmac_lib.new(
        RUNNER_SECRET.encode(), expected_msg.encode(), hashlib.sha256,
    ).hexdigest()
    if resp.response_sig != expected_sig:
        raise ValueError("Enroll response_sig mismatch — possible MITM or wrong RUNNER_SECRET")

    # Persist the assigned node_id for stable identity across reconnects.
    NODE_ID = resp.node_id
    os.makedirs(APPS_DIR, exist_ok=True)
    node_id_file = _node_id_file()
    try:
        with open(node_id_file, "w") as fh:
            fh.write(NODE_ID)
    except OSError as exc:
        log.warning("[enroll] Could not persist node_id: %s", exc)

    _client_cert_pem = resp.client_cert_pem
    _client_key_pem  = key_pem
    _ca_cert_pem     = resp.ca_cert_pem
    _server_name     = resp.server_name

    log.info(
        "[enroll] Enrolled: id=%s name=%s location=%s server=%s",
        NODE_ID, resp.node_name, resp.location_type, _server_name,
    )


def _resolve_node_id() -> str:
    """
    Restore NODE_ID from the env var or the persisted per-hostname file.

    Actual enrollment (keypair + CSR + gRPC Enroll RPC) happens in _enroll(),
    called per connect-iteration in _tunnel_loop. This function is only called
    once at startup to surface a previously-assigned ID for the async listener
    before the first tunnel connection is established.
    """
    global NODE_ID
    if NODE_ID:
        return NODE_ID
    node_id_file = _node_id_file()
    if os.path.isfile(node_id_file):
        try:
            val = open(node_id_file).read().strip()  # noqa: WPS515
            if val:
                NODE_ID = val
                log.info("[node-id] Loaded from %s: %s", node_id_file, NODE_ID)
                return NODE_ID
        except OSError as exc:
            log.warning("[node-id] Could not read %s: %s", node_id_file, exc)
    return NODE_ID


# ── ZIP extraction helpers ─────────────────────────────────────────────────────
_MAX_EXTRACT_FILE_BYTES  = 50 * 1024 * 1024   # 50 MB per-file cap
_MAX_EXTRACT_TOTAL_BYTES = 500 * 1024 * 1024  # 500 MB aggregate cap

# Pure frontend/static assets belong only in Go Core's static/apps cache (which
# serves them at /apps/{name}/) — the runner executes main.py and never serves
# these, so they are skipped on extract to keep the runner's app dir Python-only.
# manifest.json (.json) is intentionally NOT here: the runner reads its version.
_FRONTEND_ASSET_EXTS = frozenset({
    ".html", ".htm", ".css", ".js", ".mjs", ".map", ".scss", ".less",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
})


def _is_frontend_asset(member_name: str) -> bool:
    """True for pure frontend assets that should not land in the runner's app dir."""
    return os.path.splitext(member_name)[1].lower() in _FRONTEND_ASSET_EXTS


def _extract_zip_to_apps(app_name: str, zip_bytes: bytes) -> str:
    """
    Safely extract a ZIP bundle (raw bytes) into APPS_DIR/{app_name}/.

    Pure frontend assets (see _is_frontend_asset) are skipped — they belong
    only in Go Core's static/apps cache. The runner keeps Python source,
    manifest.json, requirements.txt, and vendored libs/.

    Security enforcements applied on every ZIP entry:
    - Path traversal (zip-slip): normalised member path must stay inside the
      temporary extraction directory.
    - Per-file decompression cap (_MAX_EXTRACT_FILE_BYTES): prevents single
      oversized entries from exhausting disk.
    - Aggregate decompression cap (_MAX_EXTRACT_TOTAL_BYTES): guards against
      zip-bomb payloads composed of many individually-small members.

    Returns the staged version directory path on success.
    """
    if err := _validate_app_name(app_name):
        raise ValueError(err)

    abs_apps_dir = os.path.realpath(APPS_DIR)
    os.makedirs(abs_apps_dir, exist_ok=True)

    tmp_dir = tempfile.mkdtemp(prefix=f"tmp_{app_name}_", dir=abs_apps_dir)
    total_written = 0

    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            for member in zf.infolist():
                # Normalise path and strip leading slashes to avoid root escapes.
                norm = os.path.normpath(member.filename.lstrip("/").lstrip("\\"))
                # A "../"-only path normalises to ".." — reject it explicitly.
                if norm.startswith(".."):
                    raise ValueError(
                        f"[DEPLOY] Zip-slip detected in member: {member.filename!r}"
                    )
                dest = os.path.realpath(os.path.join(tmp_dir, norm))
                # Double-check: resolved path must stay inside tmp_dir.
                if not dest.startswith(os.path.realpath(tmp_dir)):
                    raise ValueError(
                        f"[DEPLOY] Zip-slip detected in member: {member.filename!r}"
                    )

                if member.is_dir():
                    os.makedirs(dest, mode=0o755, exist_ok=True)
                    continue

                # Frontend assets live only on Go Core — the runner runs Python.
                if _is_frontend_asset(member.filename):
                    continue

                os.makedirs(os.path.dirname(dest), mode=0o755, exist_ok=True)
                file_written = 0
                with zf.open(member) as src, open(dest, "wb") as dst:
                    while True:
                        chunk = src.read(65536)
                        if not chunk:
                            break
                        file_written  += len(chunk)
                        total_written += len(chunk)
                        if file_written > _MAX_EXTRACT_FILE_BYTES:
                            raise ValueError(
                                f"[DEPLOY] Member {member.filename!r} exceeds "
                                f"{_MAX_EXTRACT_FILE_BYTES // (1 << 20)} MB cap"
                            )
                        if total_written > _MAX_EXTRACT_TOTAL_BYTES:
                            raise ValueError(
                                "[DEPLOY] Bundle exceeds aggregate decompression "
                                "cap — possible zip bomb"
                            )
                        dst.write(chunk)

        # Structural validation: main.py must exist at the bundle root.
        if not os.path.isfile(os.path.join(tmp_dir, "main.py")):
            raise ValueError(
                "[DEPLOY] Invalid bundle: main.py is required at the bundle root"
            )

        version_root = os.path.join(abs_apps_dir, ".versions", app_name)
        os.makedirs(version_root, mode=0o755, exist_ok=True)
        version_dir = os.path.join(
            version_root,
            f"{int(time.time() * 1000)}_{os.getpid()}_{uuid.uuid4().hex}",
        )
        os.rename(tmp_dir, version_dir)
        log.info("[DEPLOY] Staged app '%s' → %s", app_name, version_dir)
        return version_dir

    except Exception:
        # Always clean up the temp directory on failure.
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise


def _activate_app_version(app_name: str, version_dir: str) -> str | None:
    """
    Make version_dir the active app path.

    On POSIX, the active app path becomes a symlink so later reloads can swap
    it atomically. On Windows, fall back to a directory rename.

    Returns the previous active target when one existed.
    """
    abs_apps_dir = os.path.realpath(APPS_DIR)
    active_path = os.path.join(abs_apps_dir, app_name)
    version_dir = os.path.realpath(version_dir)
    previous_target = None

    if _IS_WINDOWS:
        if os.path.lexists(active_path):
            if os.path.isdir(active_path):
                previous_target = os.path.join(
                    abs_apps_dir,
                    ".versions",
                    app_name,
                    f"legacy_{int(time.time() * 1000)}_{os.getpid()}_{uuid.uuid4().hex}",
                )
                os.makedirs(os.path.dirname(previous_target), exist_ok=True)
                os.rename(active_path, previous_target)
            elif os.path.isfile(active_path):
                previous_target = active_path
                os.unlink(active_path)
        os.rename(version_dir, active_path)
        return previous_target

    if os.path.islink(active_path):
        previous_target = os.path.realpath(active_path)
        temp_link = f"{active_path}.link.{os.getpid()}.{uuid.uuid4().hex}"
        os.symlink(version_dir, temp_link)
        os.replace(temp_link, active_path)
        return previous_target

    if os.path.lexists(active_path):
        previous_target = os.path.join(
            abs_apps_dir,
            ".versions",
            app_name,
            f"legacy_{int(time.time() * 1000)}_{os.getpid()}_{uuid.uuid4().hex}",
        )
        os.makedirs(os.path.dirname(previous_target), exist_ok=True)
        os.rename(active_path, previous_target)

    temp_link = f"{active_path}.link.{os.getpid()}.{uuid.uuid4().hex}"
    os.symlink(version_dir, temp_link)
    os.replace(temp_link, active_path)
    return previous_target


def _fetch_app_bytes_sync(app_name: str) -> bytes | None:
    """
    Synchronous helper: fetch code_bytes for a single app from PostgreSQL.
    Used during startup preload before the asyncpg pool is initialised.
    Returns raw ZIP bytes, or None when the app is not found in the DB.
    """
    if not DATABASE_URL:
        return None
    try:
        with psycopg2.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT code_bytes FROM noderouter_core.apps WHERE app_name = %s",
                    (app_name,),
                )
                row = cur.fetchone()
        if row is None:
            return None
        return bytes(row[0])
    except Exception as exc:
        log.warning("[DEPLOY] DB fetch failed for '%s': %s", app_name, exc)
        return None


def _purge_app_modules(app_name: str) -> None:
    """
    Drop an app's synthetic package namespace from sys.modules (F2).
    Live references held by already-imported module objects keep working —
    only the import cache is cleared.
    """
    pkg_name = _app_active_pkg.pop(app_name, None)
    if pkg_name:
        for key in [k for k in sys.modules if k == pkg_name or k.startswith(pkg_name + ".")]:
            sys.modules.pop(key, None)


def _module_origin(mod) -> str | None:
    """Best-effort filesystem origin of a module (file or package dir)."""
    origin = getattr(mod, "__file__", None)
    if origin:
        return origin
    search = list(getattr(mod, "__path__", None) or [])
    return search[0] if search else None


def _import_app_module(app_name: str, app_path: str):
    """
    Import an app's main.py as `<pkg>.main` under a unique synthetic package
    whose __path__ is the app directory (F1).

    Sibling modules resolve via relative imports (`from . import utils`) into
    the same namespace — `<pkg>.utils` — so two apps shipping a `utils.py`
    can never collide in sys.modules. The package name embeds a fresh suffix
    per load, so the previous version keeps its namespace until the new load
    succeeds: a failed redeploy never breaks the still-active module.

    Bare sibling imports (`import utils`) remain supported through the
    sys.path context, but any module that resolved to a file inside the app
    dir is evicted from sys.modules once the load completes — the main module
    keeps its live reference, while the next app (or the next version of this
    one) re-imports its own copy from disk instead of hitting a stale cache
    entry (F1/F2 for the legacy import style).

    Caller must hold _import_lock in the daemon process; pool workers run one
    task at a time and may call it bare. Raises on any failure.
    """
    app_dir = os.path.realpath(os.path.dirname(app_path))
    pkg_name = f"app_{app_name}__{uuid.uuid4().hex[:8]}"

    before = set(sys.modules)

    pkg_spec = importlib.machinery.ModuleSpec(pkg_name, None, is_package=True)
    pkg_spec.submodule_search_locations = [app_dir]
    sys.modules[pkg_name] = importlib.util.module_from_spec(pkg_spec)

    spec = importlib.util.spec_from_file_location(f"{pkg_name}.main", app_path)
    if spec is None or spec.loader is None:
        sys.modules.pop(pkg_name, None)
        raise ImportError(f"failed to create import spec for app '{app_name}'")

    module = importlib.util.module_from_spec(spec)
    # Register before exec_module so circular and relative imports issued by
    # main.py's body resolve while it is still executing.
    sys.modules[spec.name] = module
    try:
        with _app_import_context(app_path):
            spec.loader.exec_module(module)
        if not callable(getattr(module, "execute", None)):
            raise ImportError(
                f"app '{app_name}' does not expose a callable execute(data) function"
            )
    except BaseException:
        for key in [k for k in sys.modules if k == pkg_name or k.startswith(pkg_name + ".")]:
            sys.modules.pop(key, None)
        raise

    # Commit: retire the previous version's namespace, then claim this one.
    old_pkg = _app_active_pkg.get(app_name)
    if old_pkg:
        for key in [k for k in sys.modules if k == old_pkg or k.startswith(old_pkg + ".")]:
            sys.modules.pop(key, None)
    _app_active_pkg[app_name] = pkg_name

    # Evict bare-name modules this load pulled in from inside the app dir
    # (legacy `import utils` siblings and vendored libs/ packages) so they
    # never satisfy another app's — or another version's — imports.
    prefix = app_dir + os.sep
    for key in set(sys.modules) - before:
        if key == pkg_name or key.startswith(pkg_name + "."):
            continue
        origin = _module_origin(sys.modules.get(key))
        if origin and os.path.realpath(origin).startswith(prefix):
            sys.modules.pop(key, None)

    return module


def _load_app(app_name: str, app_path: str | None = None):
    """
    Dynamically load an app module from disk and atomically update the registry.
    Safe to call from thread pool workers (uses threading.Lock).

    Returns (module, None) on success or (None, error_message) on failure.
    """
    if err := _validate_app_name(app_name):
        return None, err

    if app_path is None:
        app_path = _resolve_app_path(app_name)
    if app_path is None:
        return None, f"app '{app_name}' not found in {APPS_DIR}"

    try:
        with _import_lock:
            module = _import_app_module(app_name, app_path)
    except Exception as exc:
        return None, f"failed to load app '{app_name}': {exc}"

    params = set(inspect.signature(module.execute).parameters)
    # Tag the module so the sync/async injectors know which app owns it (needed
    # to scope named queries) without a reverse registry lookup.
    setattr(module, "__noderouter_app__", app_name)

    # Read the manifest version (sent in QueryRequest so Core can detect a stale
    # cache entry and reload from DB) and the per-action parameter order (used to
    # reorder a named-param dict into the positional $1..$N list Core expects).
    version = ""
    query_params: dict[str, list[str]] = {}
    manifest_path = os.path.join(os.path.dirname(app_path), "manifest.json")
    try:
        with open(manifest_path) as _mf:
            manifest = json.load(_mf)
        version = manifest.get("version", "")
        for action in manifest.get("actions", []) or []:
            name = action.get("name")
            if not name:
                continue
            query_params[name] = [
                p.get("name") for p in (action.get("params") or []) if p.get("name")
            ]
    except Exception:
        pass
    _app_versions[app_name] = version
    _app_query_params[app_name] = query_params

    with _registry_lock:
        _app_registry[app_name] = module
    _exec_params[id(module)] = params
    log.info("App loaded: %s (%s) v%s [query-injection: %s]", app_name, app_path, version or "?", "query" in params)
    return module, None


def _get_app(app_name: str):
    """Return a cached app module, or None if not yet loaded.

    B8 — Lock-free read: CPython's GIL guarantees that dict.get() is atomic,
    so no additional lock is needed for reads. _registry_lock is held only
    during writes inside _load_app, keeping the hot-path (cache-hit) free of
    any synchronisation overhead.
    """
    return _app_registry.get(app_name)


def _preload_apps() -> None:
    """
    Warm the app registry at startup.

    Primary path (DATABASE_URL set): query noderouter_core.apps, fetch each
    app's code_bytes blob, extract into APPS_DIR, and load the Python module.
    This makes PostgreSQL the Single Source of Truth — no shared filesystem
    mount between Core and Runner nodes is required.

    Fallback path (DATABASE_URL absent or query fails): scan APPS_DIR on disk
    and load whatever Python modules are already present (legacy behaviour).
    """
    os.makedirs(APPS_DIR, exist_ok=True)
    loaded = 0

    if DATABASE_URL:
        try:
            with psycopg2.connect(DATABASE_URL) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT app_name, code_bytes FROM noderouter_core.apps"
                    )
                    rows = cur.fetchall()

            log.info("[DEPLOY] Preloading %d app(s) from PostgreSQL blob store", len(rows))
            for app_name, code_bytes_raw in rows:
                if err := _validate_app_name(app_name):
                    log.warning("[DEPLOY] Preload skipped DB app '%s': %s", app_name, err)
                    continue
                try:
                    version_dir = _extract_zip_to_apps(app_name, bytes(code_bytes_raw))
                    version_main = os.path.join(version_dir, "main.py")
                    _, load_err = _load_app(app_name, version_main)
                    if load_err:
                        log.warning("[DEPLOY] Preload load error '%s': %s", app_name, load_err)
                        shutil.rmtree(version_dir, ignore_errors=True)
                    else:
                        previous_target = None
                        try:
                            previous_target = _activate_app_version(app_name, version_dir)
                        except Exception as exc:
                            log.warning("[DEPLOY] Preload activation error '%s': %s", app_name, exc)
                            shutil.rmtree(version_dir, ignore_errors=True)
                            continue
                        if previous_target and os.path.exists(previous_target):
                            shutil.rmtree(previous_target, ignore_errors=True)
                        loaded += 1
                except Exception as exc:
                    log.warning("[DEPLOY] Preload extraction error '%s': %s", app_name, exc)

            log.info("App preload from PostgreSQL complete: %d app(s) ready", loaded)
            return
        except Exception as exc:
            log.warning(
                "[DEPLOY] PostgreSQL preload failed (%s) — falling back to disk scan", exc
            )

    # Fallback: scan APPS_DIR on disk (no DATABASE_URL or DB unreachable).
    for entry in sorted(os.scandir(APPS_DIR), key=lambda e: e.name):
        app_name = None
        if entry.is_dir() and os.path.isfile(os.path.join(entry.path, "main.py")):
            app_name = entry.name
        elif entry.is_file() and entry.name.endswith(".py") and entry.name != "__init__.py":
            app_name = entry.name[:-3]
        if app_name:
            _, err = _load_app(app_name)
            if err:
                log.warning("Preload skipped — %s", err)
            else:
                loaded += 1
    log.info("App preload from disk complete: %d app(s) ready", loaded)


# ── Isolated subprocess entry point ───────────────────────────────────────────
def _execute_app_isolated(app_name: str, app_path: str, data: dict) -> dict:
    """
    Run an app inside a pooled worker subprocess (via ProcessPoolExecutor).

    Workers are reused across jobs of different apps, so the app's module
    namespace is rebuilt from disk on every invocation and torn down in the
    finally block: a redeploy is always picked up by the next job, and one
    app's modules can never satisfy another app's imports (F1/F2) — at the
    cost of one re-import per job. The path context stays open across
    execute() so lazy imports inside app code resolve (F3).

    App SQL runs exclusively through the injected query() client, which
    marshals to the parent process over the Manager bridge and out to Core
    (named-queries-only). report_progress() likewise bridges to the parent's
    job-table writer. DATABASE_URL is stripped from this subprocess by
    _worker_init, so apps cannot open a direct Postgres connection.
    """
    before = set(sys.modules)
    _purge_app_modules(app_name)
    try:
        module = _import_app_module(app_name, app_path)
        params = set(inspect.signature(module.execute).parameters)
        kwargs = {}
        if "query" in params:
            kwargs["query"] = lambda name, p=None: _worker_query(app_name, name, p)
        if "report_progress" in params:
            job_id = data.get("_job_id", "")
            kwargs["report_progress"] = lambda pct, _jid=job_id: _worker_report_progress(_jid, pct)
        with _app_import_context(app_path):
            return module.execute(data, **kwargs)
    finally:
        _purge_app_modules(app_name)
        # Drop anything this job imported from inside APPS_DIR (e.g. lazy bare
        # imports during execute) so it cannot leak into the next job this
        # worker picks up. Site-packages stay cached to keep workers warm.
        apps_root = os.path.realpath(APPS_DIR) + os.sep
        for key in set(sys.modules) - before:
            origin = _module_origin(sys.modules.get(key))
            if origin and os.path.realpath(origin).startswith(apps_root):
                sys.modules.pop(key, None)


def _run_sync_execute(module, payload: dict):
    """
    Execute a sync app in a thread-pool worker, injecting a blocking query()
    client when the app declares it. Apps hold no DB connection — query()
    bridges to Core over the tunnel (named-queries-only).
    """
    fn = getattr(module, "execute")
    params = _exec_params.get(id(module)) or set(inspect.signature(fn).parameters)
    app_name = getattr(module, "__noderouter_app__", "")

    kwargs = {}
    if "query" in params:
        kwargs["query"] = lambda name, p=None: _query_threadsafe(name, p, app_name=app_name)

    # F3: keep the app dir + libs/ importable across the call so lazy imports
    # inside execute() resolve.
    with _app_import_context(module.__file__):
        return fn(payload, **kwargs)


# ── DB helpers (async, asyncpg) ────────────────────────────────────────────────
_ALLOWED_JOB_FIELDS = frozenset({"status", "progress", "result", "error_message"})
_JOB_TABLE = "noderouter_core.job_queue"


async def _update_job(job_id: str, **fields) -> None:
    """
    Persist job state back to job_queue via the asyncpg pool.
    Only whitelisted column names are accepted to prevent injection.
    Progress writes should be batched (Blueprint 2 MVCC mitigation).
    """
    invalid = set(fields) - _ALLOWED_JOB_FIELDS
    if invalid:
        raise ValueError(f"Disallowed job fields: {invalid}")
    set_clause = ", ".join(f"{k} = ${i+2}" for i, k in enumerate(fields))
    values = list(fields.values())
    async with _db_pool.acquire() as conn:
        await conn.execute(
            f"UPDATE {_JOB_TABLE} SET {set_clause}, updated_at = NOW() WHERE id = $1",
            job_id, *values,
        )


# ── Named Query Client ─────────────────────────────────────────────────────────
class QueryError(Exception):
    """Raised when a named query fails. Carries an HTTP-style status code."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def _map_query_params(app_name: str, query_name: str, params):
    """
    Normalise an app's query params into the positional list Core binds to the
    named SQL's $1..$N placeholders.

    Apps call query("action", {...}) with a dict keyed by the parameter names
    declared for that action in manifest.json, or query("action", [...]) with an
    already-positional list. A dict is reordered to match the manifest's `params`
    order (missing keys default to None); a list/tuple — or None — passes through
    unchanged. A scalar is wrapped as a single-element list.

    Raises QueryError(400) when a dict is supplied for an action that has no
    parameter schema in the manifest, since the bind order is then unknown.
    """
    if params is None:
        return []
    if isinstance(params, dict):
        order = _app_query_params.get(app_name, {}).get(query_name)
        if order is None:
            raise QueryError(
                400,
                f"query '{query_name}' has no parameter schema in manifest.json "
                f"for app '{app_name}' — pass params as a positional list",
            )
        return [params.get(n) for n in order]
    if isinstance(params, (list, tuple)):
        return list(params)
    return [params]


async def _send_query(query_name: str, params, app_name: str):
    """
    Send a registered named-query request to Core over the tunnel and await the
    QueryResponse. Runs on the event loop. Returns the decoded rows (a list) or
    raises QueryError. This is the single egress point for ALL app SQL.
    """
    outq = _tunnel_outq
    if outq is None or _event_loop is None:
        raise QueryError(503, "tunnel not connected")

    # Reorder a named-param dict into Core's positional $1..$N list (no-op for a
    # list/None); raises QueryError before a qid is allocated on a bad dict.
    positional = _map_query_params(app_name, query_name, params)

    qid = uuid.uuid4().hex
    fut: asyncio.Future = _event_loop.create_future()
    _query_pending[qid] = fut
    try:
        outq.put_nowait(tunnel_pb2.RunnerFrame(
            query_request=tunnel_pb2.QueryRequest(
                qid=qid,
                query_name=query_name,
                params=json.dumps(positional).encode(),
                app_name=app_name or "",
                app_version=_app_versions.get(app_name, "") if app_name else "",
            ),
        ))
        try:
            status, rows, error = await asyncio.wait_for(fut, timeout=QUERY_TIMEOUT)
        except asyncio.TimeoutError:
            raise QueryError(504, f"query '{query_name}' timed out")
    finally:
        _query_pending.pop(qid, None)

    if status != 200:
        raise QueryError(status, error or f"query '{query_name}' failed")
    return rows


def _resolve_query_response(qr) -> None:
    """Resolve the pending future for a QueryResponse CoreFrame (event-loop side)."""
    fut = _query_pending.get(qr.qid)
    if fut is None or fut.done():
        return
    rows = []
    if qr.rows:
        try:
            rows = json.loads(qr.rows)
        except Exception:
            rows = []
    fut.set_result((qr.status, rows, qr.error))


def _fail_pending_queries(reason: str) -> None:
    """Fail every in-flight query (called when the tunnel drops)."""
    for qid, fut in list(_query_pending.items()):
        if not fut.done():
            fut.set_result((503, [], reason))
    _query_pending.clear()


def _query_threadsafe(query_name: str, params=None, *, app_name: str):
    """
    Blocking named-query call for sync apps running in the thread pool. Bridges
    into the event loop via run_coroutine_threadsafe. Raises QueryError.
    """
    if _event_loop is None:
        raise QueryError(503, "event loop not ready")
    fut = asyncio.run_coroutine_threadsafe(
        _send_query(query_name, params, app_name), _event_loop,
    )
    return fut.result(timeout=QUERY_TIMEOUT + 5)


# ── Subprocess → parent bridge (async-job workers) ────────────────────────────
def _worker_init(req_q, resp_qs, idx_counter, idx_lock) -> None:
    """
    ProcessPoolExecutor initializer. Assigns each worker a stable slot index and
    stashes the Manager queues so query()/report_progress() can marshal to the
    parent. Strips DATABASE_URL so app code in this subprocess CANNOT open a
    direct Postgres connection (named-queries-only enforcement).
    """
    global _W_REQ_Q, _W_RESP_Q, _W_IDX
    with idx_lock:
        i = idx_counter.value
        idx_counter.value = i + 1
    _W_IDX = i % len(resp_qs)
    _W_REQ_Q = req_q
    _W_RESP_Q = resp_qs[_W_IDX]
    os.environ.pop("DATABASE_URL", None)


def _worker_query(app_name: str, query_name: str, params=None):
    """Subprocess-side query(): marshals to the parent and blocks for the result."""
    if _W_REQ_Q is None or _W_RESP_Q is None:
        raise RuntimeError("query bridge not initialised in this worker")
    _W_REQ_Q.put(("query", _W_IDX, {
        "name": query_name, "params": params, "app_name": app_name,
    }))
    status, rows, error = _W_RESP_Q.get()
    if status != 200:
        raise RuntimeError(f"query '{query_name}' failed ({status}): {error}")
    return rows


def _worker_report_progress(job_id: str, percent) -> None:
    """Subprocess-side report_progress(): fire-and-forget to the parent."""
    if _W_REQ_Q is None or not job_id:
        return
    try:
        _W_REQ_Q.put(("progress", _W_IDX, {"job_id": job_id, "progress": int(percent)}))
    except Exception:
        pass


def _bridge_drain_loop() -> None:
    """
    Parent-side drainer (daemon thread). Forwards worker query/progress requests
    onto the event loop WITHOUT blocking on each one: query results are returned
    to the worker via a done-callback so many subprocess queries run concurrently.
    """
    while True:
        try:
            kind, idx, payload = _bridge_req_q.get()
        except (EOFError, OSError):
            return
        if kind == "__stop__":
            return
        if _event_loop is None:
            if kind == "query":
                _bridge_resp_qs[idx].put((503, None, "event loop not ready"))
            continue

        if kind == "query":
            coro = _send_query(payload["name"], payload["params"], payload["app_name"])
            cfut = asyncio.run_coroutine_threadsafe(coro, _event_loop)

            def _done(f, _idx=idx):
                try:
                    _bridge_resp_qs[_idx].put((200, f.result(), ""))
                except QueryError as qe:
                    _bridge_resp_qs[_idx].put((qe.status, None, str(qe)))
                except Exception as exc:  # noqa: BLE001
                    _bridge_resp_qs[_idx].put((500, None, str(exc)))

            cfut.add_done_callback(_done)
        elif kind == "progress":
            asyncio.run_coroutine_threadsafe(
                _update_job(payload["job_id"], progress=payload["progress"]),
                _event_loop,
            )


async def _fetch_pending_job(job_id: str) -> tuple[str, dict] | None:
    """Fetch (app_name, payload) for a pending job assigned to this node."""
    async with _db_pool.acquire() as conn:
        if NODE_ID:
            row = await conn.fetchrow(
                f"SELECT app_name, payload FROM {_JOB_TABLE} "
                "WHERE id = $1 AND node_id = $2 AND status = 'pending'",
                job_id, NODE_ID,
            )
        else:
            row = await conn.fetchrow(
                f"SELECT app_name, payload FROM {_JOB_TABLE} "
                "WHERE id = $1 AND status = 'pending'",
                job_id,
            )
    if row is None:
        return None
    raw_payload = row["payload"]
    payload = raw_payload if isinstance(raw_payload, dict) else json.loads(raw_payload or "{}")
    return row["app_name"], payload


async def _claim_job(job_id: str) -> str | None:
    """
    Atomically transition a pending job to 'running' using SKIP LOCKED.
    Returns the claimed job_id, or None if already claimed by another worker.
    """
    async with _db_pool.acquire() as conn:
        if NODE_ID:
            row = await conn.fetchrow(
                f"""UPDATE {_JOB_TABLE}
                       SET status = 'running', updated_at = NOW()
                     WHERE id = (
                         SELECT id FROM {_JOB_TABLE}
                          WHERE id = $1 AND node_id = $2 AND status = 'pending'
                          FOR UPDATE SKIP LOCKED LIMIT 1
                     )
                    RETURNING id""",
                job_id, NODE_ID,
            )
        else:
            row = await conn.fetchrow(
                f"""UPDATE {_JOB_TABLE}
                       SET status = 'running', updated_at = NOW()
                     WHERE id = (
                         SELECT id FROM {_JOB_TABLE}
                          WHERE id = $1 AND status = 'pending'
                          FOR UPDATE SKIP LOCKED LIMIT 1
                     )
                    RETURNING id""",
                job_id,
            )
    return str(row["id"]) if row else None


def _recover_stuck_jobs_sync() -> None:
    """
    At startup, reset any jobs stuck in 'running' from a prior crashed instance
    back to 'pending' so they can be re-dispatched.
    Uses synchronous psycopg2 — called before the asyncio loop is fully running.
    """
    if not DATABASE_URL:
        return
    try:
        with psycopg2.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                if NODE_ID:
                    cur.execute(
                        f"UPDATE {_JOB_TABLE} SET status='pending', updated_at=NOW() "
                        "WHERE node_id=%s AND status='running'",
                        (NODE_ID,),
                    )
                else:
                    cur.execute(
                        f"UPDATE {_JOB_TABLE} SET status='pending', updated_at=NOW() "
                        "WHERE status='running'"
                    )
                count = cur.rowcount
            conn.commit()
        if count:
            log.info("Startup recovery: reset %d stuck running job(s) to 'pending'", count)
    except Exception as exc:
        log.warning("Startup job recovery failed: %s", exc)


# ── Async job coroutine ────────────────────────────────────────────────────────
async def _run_async_job(job_id: str, app_name: str, payload: dict) -> None:
    """
    Claim and execute an async job in the isolated ProcessPoolExecutor.
    The SKIP LOCKED pattern guarantees only one worker claims each job even when
    multiple runners receive the same NOTIFY simultaneously.
    """
    claimed_id = await _claim_job(job_id)
    if claimed_id is None:
        log.debug("Job %s already claimed or not assigned to this node — skipping.", job_id)
        return

    log.info("Claimed async job %s (app: %s)", job_id, app_name)

    app_path = _resolve_app_path(app_name)
    if app_path is None:
        await _update_job(job_id, status="failed", error_message=f"app '{app_name}' not found")
        log.warning("Async job %s failed — app '%s' not found", job_id, app_name)
        return

    payload = {**payload, "_job_id": job_id}

    loop = asyncio.get_running_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(_process_pool, _execute_app_isolated, app_name, app_path, payload),
            timeout=300.0,
        )

        # Strip _actions before storing the job result.
        actions_to_dispatch = []
        if isinstance(result, dict) and "_actions" in result:
            raw = result.pop("_actions")
            if isinstance(raw, list):
                actions_to_dispatch = raw

        result_json = json.dumps(result) if not isinstance(result, str) else result
        await _update_job(job_id, status="completed", progress=100, result=result_json)
        log.info("Async job %s completed (app: %s)", job_id, app_name)

        # Emit one pg_notify per action so Core's action_listener can dispatch
        # notifications to subscribed users.
        if actions_to_dispatch and _db_pool:
            triggered_at = datetime.now(timezone.utc).isoformat()
            for act in actions_to_dispatch:
                if not isinstance(act, dict) or not act.get("name"):
                    continue
                try:
                    evt = json.dumps({
                        "app_name":     app_name,
                        "action_name":  act["name"],
                        "payload":      act.get("payload"),
                        "job_id":       job_id,
                        "triggered_at": triggered_at,
                    })
                    async with _db_pool.acquire() as conn:
                        await conn.execute("SELECT pg_notify('app_action_triggered', $1)", evt)
                    log.info(
                        "[action] Dispatched async action: app=%s action=%s job=%s",
                        app_name, act["name"], job_id,
                    )
                except Exception as exc:
                    log.warning(
                        "[action] PG notify failed app=%s action=%s: %s",
                        app_name, act.get("name"), exc,
                    )

    except asyncio.TimeoutError:
        await _update_job(job_id, status="failed", error_message="job timed out after 300 s")
        log.error("Async job %s timed out", job_id)
    except Exception as exc:
        await _update_job(job_id, status="failed", error_message=str(exc))
        log.exception("Async job %s raised an unhandled error", job_id)


# ── B10: Async-capable dispatch ───────────────────────────────────────────────
async def _dispatch_execute(module, payload: dict):
    """
    Dispatch module.execute(payload) via the appropriate execution path.

    B10 — Thread hand-off elimination for async apps:
      sync  execute(data)       → loop.run_in_executor (thread pool, GIL-safe)
      async execute(data) (coro)→ awaited directly in the event loop (zero
                                  thread context-switch overhead, ~50–200 µs
                                  saved per call for fast non-blocking apps)

    Apps opt in to the async path by declaring `async def execute(data: dict)`.
    Sync apps continue to run in the ThreadPoolExecutor as before.
    """
    fn = getattr(module, "execute")
    if inspect.iscoroutinefunction(fn):
        params = _exec_params.get(id(module)) or set(inspect.signature(fn).parameters)
        app_name = getattr(module, "__noderouter_app__", "")
        kwargs = {}
        if "query" in params:
            async def _q(name, p=None, _app=app_name):
                return await _send_query(name, p, _app)
            kwargs["query"] = _q
        # F3: pin the app's import paths across await points; the ref-counted
        # context tolerates interleaved executions of other apps.
        with _app_import_context(module.__file__):
            return await fn(payload, **kwargs)
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_thread_pool, _run_sync_execute, module, payload)


# ── Sync request handler (tunnel Request frame) ───────────────────────────────
async def _handle_req(send, req: tunnel_pb2.Request) -> None:
    """
    Handle a single synchronous Request frame received from Core over the Tunnel.

    `send` is outq.put_nowait — synchronous, unbounded, always-succeeds so
    the always-respond guarantee (B11) holds without await in the error path.

    Performance improvements applied:
      B8  Lock-free _get_app() read — GIL makes dict.get() atomic; no lock needed.
      B9  _sync_semaphore bounds concurrent task count to SYNC_MAX_WORKERS × 4,
          preventing unbounded asyncio task accumulation under traffic bursts.
      B10 _dispatch_execute() runs async apps directly in the event loop,
          eliminating the ~50–200 µs thread context-switch for fast apps.
      B11 _send_res() catches serialization errors and returns a 500 frame so
          the Core goroutine is never silently abandoned (which would timeout).
      B12 Per-app asyncio.Lock coalesces concurrent cache-miss loads so the
          same module is never imported in parallel by multiple coroutines.
    """
    rid      = req.rid
    app_name = req.app
    payload  = json.loads(req.payload) if req.payload else {}

    # B11: catch serialization failures so Core's goroutine always gets a frame.
    def _send_res(status: int, body: dict) -> None:
        try:
            body_bytes = json.dumps(body).encode()
        except (TypeError, ValueError) as exc:
            log.error("Sync res serialization error rid=%s: %s", rid, exc)
            body_bytes = json.dumps({"error": "response serialization failed"}).encode()
        try:
            send(tunnel_pb2.RunnerFrame(
                response=tunnel_pb2.Response(rid=rid, status=status, body=body_bytes),
            ))
        except Exception as exc:
            log.debug("Tunnel send failed rid=%s: %s", rid, exc)

    if err := _validate_app_name(app_name):
        _send_res(400, {"error": err})
        return

    # B8: lock-free registry read (GIL-safe).
    module = _get_app(app_name)
    if module is None:
        # B12: coalesce concurrent misses for the same app_name.
        # Only the first coroutine through the app_lock calls _load_app;
        # others wait, then re-check the registry before re-loading.
        async with _app_load_locks_mu:
            if app_name not in _app_load_locks:
                _app_load_locks[app_name] = asyncio.Lock()
            app_lock = _app_load_locks[app_name]

        async with app_lock:
            module = _get_app(app_name)  # re-check: another coroutine may have loaded it
            if module is None:
                module, load_err = await asyncio.to_thread(_load_app, app_name)
                if load_err:
                    _send_res(404, {"error": load_err})
                    return

    try:
        if isinstance(payload, (str, bytes)):
            try:
                payload = json.loads(payload)
            except Exception:
                payload = {}

        # B10: sync apps → thread pool; async apps → event loop directly.
        result = await _dispatch_execute(module, payload)

        # Strip _actions before serialising the response.
        actions_to_dispatch = []
        if isinstance(result, dict) and "_actions" in result:
            raw = result.pop("_actions")
            if isinstance(raw, list):
                actions_to_dispatch = raw

        _send_res(200, result if isinstance(result, dict) else {"result": result})

        # Send action frames after the response so the calling client is
        # unblocked before we fire notifications.
        for act in actions_to_dispatch:
            if not isinstance(act, dict) or not act.get("name"):
                continue
            try:
                act_payload = act.get("payload") or {}
                send(tunnel_pb2.RunnerFrame(
                    action=tunnel_pb2.Action(
                        app_name=app_name,
                        action_name=act["name"],
                        payload=json.dumps(act_payload).encode(),
                    ),
                ))
                log.info("[action] Sent action frame: app=%s action=%s", app_name, act["name"])
            except Exception as exc:
                log.warning(
                    "[action] Frame send failed app=%s action=%s: %s",
                    app_name, act.get("name"), exc,
                )
    except Exception as exc:
        log.exception("Sync execute error: app=%s rid=%s", app_name, rid)
        _send_res(500, {"error": str(exc)})


async def _handle_req_with_permit(send, req: tunnel_pb2.Request) -> None:
    try:
        await _handle_req(send, req)
    finally:
        if _sync_semaphore is not None:
            _sync_semaphore.release()


# ── gRPC mTLS Tunnel Loop ─────────────────────────────────────────────────────
async def _tunnel_loop() -> None:
    """
    Persistent outbound gRPC mTLS Tunnel to Go Core.

    Each (re)connect iteration:
      1. Enroll — generate ephemeral ECDSA keypair + CSR, send HMAC-signed
         Enroll RPC to Core's plaintext listener, receive signed client cert +
         CA bundle. Core restarts rotate the per-boot CA; re-enrollment makes
         this self-healing without any manual intervention.
      2. Dial — open a secure_channel with the enrolled certs (mTLS).
      3. Stream — bidirectional Tunnel RPC; dispatch CoreFrames inbound,
         queue RunnerFrames outbound via asyncio.Queue.

    Frame types (Core → Runner): hello, ping, request, event, query_response
    Frame types (Runner → Core): pong, response, action, query_request
    """
    global _tunnel_outq
    attempt = 0

    while not _shutdown_event.is_set():
        # ── 1. Enroll: get fresh certs from Core's ephemeral CA ───────────────
        try:
            await asyncio.to_thread(_enroll)
        except asyncio.CancelledError:
            return
        except Exception as exc:
            delay = _backoff(attempt)
            log.error("[tunnel] Enroll failed: %s — retrying in %.1fs", exc, delay)
            attempt += 1
            try:
                await asyncio.wait_for(_shutdown_event.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass
            continue

        # ── 2. Dial Core with mTLS using the enrolled certs ───────────────────
        channel_creds = grpc.ssl_channel_credentials(
            root_certificates=_ca_cert_pem,
            private_key=_client_key_pem,
            certificate_chain=_client_cert_pem,
        )
        channel_opts = [
            ("grpc.ssl_target_name_override",     _server_name),
            ("grpc.max_receive_message_length",   16 << 20),
            ("grpc.max_send_message_length",       16 << 20),
            ("grpc.keepalive_time_ms",             60_000),
            ("grpc.keepalive_permit_without_calls", 1),
        ]

        try:
            async with grpc.aio.secure_channel(
                CORE_GRPC_TARGET, channel_creds, options=channel_opts,
            ) as channel:
                stub = tunnel_pb2_grpc.TunnelServiceStub(channel)
                outq: asyncio.Queue = asyncio.Queue()

                async def _outgoing():
                    while True:
                        frame = await outq.get()
                        if frame is None:
                            return
                        yield frame

                call = stub.Tunnel(_outgoing())
                # Publish the outbound queue so the named-query client can send
                # QueryRequest frames while this stream is live.
                _tunnel_outq = outq
                attempt = 0
                log.info("[tunnel] Connected to %s (node_id=%s)", CORE_GRPC_TARGET, NODE_ID)

                try:
                    async for core_frame in call:
                        which = core_frame.WhichOneof("frame")
                        if which == "hello":
                            log.info(
                                "[tunnel] Hello: node_id=%s node_name=%s",
                                core_frame.hello.node_id, core_frame.hello.node_name,
                            )
                        elif which == "ping":
                            outq.put_nowait(tunnel_pb2.RunnerFrame(pong=tunnel_pb2.Pong()))
                        elif which == "request":
                            req  = core_frame.request
                            send = outq.put_nowait
                            if _sync_semaphore is None:
                                asyncio.create_task(_handle_req(send, req))
                            else:
                                await _sync_semaphore.acquire()
                                try:
                                    asyncio.create_task(_handle_req_with_permit(send, req))
                                except Exception:
                                    _sync_semaphore.release()
                                    raise
                        elif which == "query_response":
                            _resolve_query_response(core_frame.query_response)
                        # "event" frames from Core (hub broadcasts) — runner ignores
                finally:
                    _tunnel_outq = None
                    _fail_pending_queries("tunnel disconnected")
                    outq.put_nowait(None)  # unblock _outgoing generator

        except asyncio.CancelledError:
            return
        except grpc.aio.AioRpcError as exc:
            code = exc.code()
            if code == grpc.StatusCode.PERMISSION_DENIED:
                # Node row deleted — clear cached id so next enroll creates a fresh one.
                log.warning(
                    "[tunnel] PERMISSION_DENIED (node_id=%s deleted?) — "
                    "clearing cached id and re-enrolling immediately",
                    NODE_ID,
                )
                _clear_persisted_node_id()
                attempt = 0
                continue
            delay = _backoff(attempt)
            log.error(
                "[tunnel] gRPC error %s: %s — reconnecting in %.1fs",
                code, exc.details(), delay,
            )
            attempt += 1
            try:
                await asyncio.wait_for(_shutdown_event.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass
        except Exception as exc:
            delay = _backoff(attempt)
            log.error("[tunnel] Error: %s — reconnecting in %.1fs", exc, delay)
            attempt += 1
            try:
                await asyncio.wait_for(_shutdown_event.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass


# ── App pull & hot-reload coroutine ───────────────────────────────────────────
async def _pull_and_reload_app(app_name: str) -> None:
    """
    Fetch the latest code_bytes blob for `app_name` from noderouter_core.apps,
    extract the ZIP into APPS_DIR/{app_name}/, and hot-reload the Python module
    so in-flight sync requests immediately use the updated code.

    Called as an asyncio.Task from the _on_app_updated NOTIFY callback.
    All blocking I/O (DB fetch, ZIP extraction) runs in the thread pool.
    """
    try:
        # Fetch raw ZIP bytes from PostgreSQL using the asyncpg connection pool.
        if _db_pool is None:
            log.warning(
                "[DEPLOY] app_updated: DB pool not ready — cannot pull '%s'", app_name
            )
            return

        async with _db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT code_bytes FROM noderouter_core.apps WHERE app_name = $1",
                app_name,
            )

        if row is None:
            log.warning("[DEPLOY] app_updated: '%s' not found in DB", app_name)
            return

        zip_bytes = bytes(row["code_bytes"])
        log.info(
            "[DEPLOY] app_updated: fetched %d bytes for '%s' — extracting",
            len(zip_bytes), app_name,
        )

        # Extraction is CPU/IO-bound; offload to the thread pool.
        version_dir = await asyncio.to_thread(_extract_zip_to_apps, app_name, zip_bytes)

        version_main = os.path.join(version_dir, "main.py")

        # Load the staged version first so a bad deploy never displaces the
        # currently active app.
        _, load_err = await asyncio.to_thread(_load_app, app_name, version_main)
        if load_err:
            log.warning(
                "[DEPLOY] app_updated: load error for '%s': %s", app_name, load_err
            )
            shutil.rmtree(version_dir, ignore_errors=True)
        else:
            previous_target = None
            try:
                previous_target = await asyncio.to_thread(_activate_app_version, app_name, version_dir)
            except Exception as exc:
                log.warning("[DEPLOY] app_updated: activation error for '%s': %s", app_name, exc)
                shutil.rmtree(version_dir, ignore_errors=True)
                return
            if previous_target and os.path.exists(previous_target):
                shutil.rmtree(previous_target, ignore_errors=True)
            log.info(
                "[DEPLOY] Extraction completed locally, broadcasting 'app_updated' "
                "notification — app=%s hot-reloaded successfully", app_name,
            )

    except Exception as exc:
        log.exception(
            "[DEPLOY] app_updated: unhandled error pulling/reloading '%s': %s",
            app_name, exc,
        )


async def _purge_local_app(app_name: str) -> None:
    """
    Drop an app from this runner entirely in response to NOTIFY app_deleted.

    Evicts the app from the in-memory registry (so the sync path stops serving
    it) and removes its on-disk files — the active path (symlink or directory)
    plus every staged version under .versions/. Mirrors the cache purge Go Core
    performs when an app is deleted from the admin app-management screen.

    In-flight executions keep their own live module reference, so a delete that
    races a request does not break the request already running.
    """
    if err := _validate_app_name(app_name):
        log.warning("[DELETE] app_deleted ignored for '%s': %s", app_name, err)
        return

    with _registry_lock:
        module = _app_registry.pop(app_name, None)
    if module is not None:
        _exec_params.pop(id(module), None)
    _app_versions.pop(app_name, None)
    _app_query_params.pop(app_name, None)
    _purge_app_modules(app_name)

    # Remove on-disk files. app_name is regex-validated above (no separators or
    # "..") so these joins cannot escape APPS_DIR.
    abs_apps_dir = os.path.realpath(APPS_DIR)
    active_path = os.path.join(abs_apps_dir, app_name)
    try:
        if os.path.islink(active_path) or os.path.isfile(active_path):
            os.unlink(active_path)
        elif os.path.isdir(active_path):
            shutil.rmtree(active_path, ignore_errors=True)
    except OSError as exc:
        log.warning("[DELETE] Could not remove active path for '%s': %s", app_name, exc)
    shutil.rmtree(os.path.join(abs_apps_dir, ".versions", app_name), ignore_errors=True)

    log.info("[DELETE] Purged app '%s' from runner registry and disk", app_name)


# ── PostgreSQL LISTEN Daemon (asyncpg) ─────────────────────────────────────────
async def _async_listener_loop() -> None:
    """
    Persistent PostgreSQL LISTEN daemon via asyncpg.
    Listens on new_job (async job dispatch), app_updated (hot-reload), and
    app_deleted (local purge). Reconnects automatically with exponential backoff.
    """
    log.info("Async listener started — LISTEN new_job + app_updated + app_deleted (node_id: %s)", NODE_ID)
    attempt = 0

    async def _on_new_job(conn, pid, channel, payload):
        job_id = (payload or "").strip()
        if not job_id:
            return
        log.info("Received NOTIFY new_job: job_id=%s", job_id)
        try:
            result = await _fetch_pending_job(job_id)
            if result is None:
                log.debug("Job %s is not assigned to this node — ignored.", job_id)
                return
            job_app_name, job_payload = result
        except Exception as exc:
            log.warning("Failed to fetch job %s metadata: %s", job_id, exc)
            return
        asyncio.create_task(_run_async_job(job_id, job_app_name, job_payload))

    async def _on_app_updated(conn, pid, channel, payload):
        name = (payload or "").strip()
        if not name:
            return
        if err := _validate_app_name(name):
            log.warning("[DEPLOY] app_updated ignored for '%s': %s", name, err)
            return
        log.info("[DEPLOY] NOTIFY app_updated: pulling '%s' from PostgreSQL blob store", name)
        asyncio.create_task(_pull_and_reload_app(name))

    async def _on_app_deleted(conn, pid, channel, payload):
        name = (payload or "").strip()
        if not name:
            return
        log.info("[DELETE] NOTIFY app_deleted: purging '%s' from this runner", name)
        asyncio.create_task(_purge_local_app(name))

    while not _shutdown_event.is_set():
        conn = None
        try:
            conn = await asyncpg.connect(DATABASE_URL)
            await conn.add_listener("new_job",     _on_new_job)
            await conn.add_listener("app_updated", _on_app_updated)
            await conn.add_listener("app_deleted", _on_app_deleted)
            log.info("Async listener: LISTEN channels registered")
            attempt = 0
            # Park until shutdown or connection drop.
            await _shutdown_event.wait()
        except asyncio.CancelledError:
            return
        except Exception as exc:
            delay = _backoff(attempt)
            log.error("Async listener error: %s — reconnecting in %.1fs", exc, delay)
            attempt += 1
            try:
                await asyncio.wait_for(_shutdown_event.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass
        finally:
            if conn and not conn.is_closed():
                with contextlib.suppress(Exception):
                    await conn.close()


# ── Entry point ────────────────────────────────────────────────────────────────
async def main() -> None:
    global _shutdown_event, _db_pool, _sync_semaphore, _app_load_locks_mu, _event_loop
    _shutdown_event = asyncio.Event()

    # B9: initialise semaphore now that the event loop is running.
    # Capacity = SYNC_MAX_WORKERS × 4 → queue depth of 4× the thread pool size
    # before backpressure kicks in. Tasks that exceed this wait here rather than
    # spawning without bound and exhausting asyncio / OS resources.
    _sync_semaphore = asyncio.Semaphore(SYNC_MAX_WORKERS * 4)

    # B12: asyncio.Lock objects must be created inside the running event loop.
    _app_load_locks_mu = asyncio.Lock()

    loop = asyncio.get_running_loop()
    _event_loop = loop  # published for the named-query client (thread/subprocess bridges)
    if not _IS_WINDOWS:
        loop.add_signal_handler(signal.SIGTERM, _shutdown_event.set)
        loop.add_signal_handler(signal.SIGINT,  _shutdown_event.set)
    # Windows: KeyboardInterrupt is caught at the asyncio.run() level below.

    log.info("=" * 60)
    log.info("Noderouter Python Runner — gRPC mTLS Tunnel")
    log.info("  Tunnel target : %s", CORE_GRPC_TARGET)
    log.info("  Enroll target : %s", CORE_ENROLL_TARGET)
    log.info("  Node ID       : %s", NODE_ID or "(enrolling on first connect…)")
    log.info("  Apps          : %s", APPS_DIR)
    log.info("  Async Chan    : %s", "enabled" if DATABASE_URL else "disabled (DATABASE_URL not set)")
    log.info("  Async Workers : %d", ASYNC_MAX_WORKERS)
    log.info("  Sync Workers  : %d", SYNC_MAX_WORKERS)
    log.info("=" * 60)

    # Resolve NODE_ID: env var → persisted file (enrollment happens in _tunnel_loop).
    # Must run after app preload so APPS_DIR exists for the .node_id file.
    await asyncio.to_thread(_resolve_node_id)
    if NODE_ID:
        log.info("  Node ID      : %s (resolved)", NODE_ID)

    # Preload apps synchronously before accepting any tunnel requests.
    await asyncio.to_thread(_preload_apps)

    # Start the subprocess→parent query bridge drainer (daemon thread). It
    # forwards async-job worker query()/report_progress() calls onto this loop.
    if _bridge_req_q is not None:
        threading.Thread(target=_bridge_drain_loop, name="query-bridge", daemon=True).start()
        log.info("Query bridge drainer started (async-job workers → tunnel)")

    if DATABASE_URL:
        _db_pool = await asyncpg.create_pool(
            DATABASE_URL,
            min_size=2,
            max_size=ASYNC_MAX_WORKERS + 4,
        )
        log.info("asyncpg pool initialized (min=2, max=%d)", ASYNC_MAX_WORKERS + 4)
        _recover_stuck_jobs_sync()
        asyncio.create_task(_async_listener_loop())
    else:
        log.info("Async channel disabled — set DATABASE_URL to enable.")

    asyncio.create_task(_tunnel_loop())

    await _shutdown_event.wait()
    log.info("Shutting down noderouter-runner…")

    # Stop the bridge drainer so its blocking get() unwinds cleanly.
    if _bridge_req_q is not None:
        try:
            _bridge_req_q.put(("__stop__", 0, None))
        except Exception:
            pass

    if _db_pool:
        await _db_pool.close()
    if _process_pool:
        _process_pool.shutdown(wait=False)
    if _thread_pool:
        _thread_pool.shutdown(wait=False)


if __name__ == "__main__":
    if not RUNNER_SECRET:
        log.warning("RUNNER_SECRET is not set — HMAC auth disabled (dev mode only)")

    # Subprocess→parent query bridge primitives. Created via a Manager so the
    # queue proxies are picklable into ProcessPoolExecutor workers. One response
    # queue per worker slot (with 4× headroom for crash-respawned workers).
    _bridge_resp_slots = max(ASYNC_MAX_WORKERS, 1) * 4
    _mp_manager = multiprocessing.Manager()
    _bridge_req_q = _mp_manager.Queue()
    _bridge_resp_qs = [_mp_manager.Queue() for _ in range(_bridge_resp_slots)]
    _bridge_idx = _mp_manager.Value("i", 0)
    _bridge_idx_lock = _mp_manager.Lock()

    # Initialise executor pools before asyncio.run() to avoid Windows spawn recursion:
    # ProcessPoolExecutor uses 'spawn' on Windows, which re-imports this module in
    # every subprocess — module-level pool creation would cause infinite spawning.
    # Each worker runs _worker_init to claim a slot and strip DATABASE_URL.
    _process_pool = concurrent.futures.ProcessPoolExecutor(
        max_workers=ASYNC_MAX_WORKERS,
        initializer=_worker_init,
        initargs=(_bridge_req_q, _bridge_resp_qs, _bridge_idx, _bridge_idx_lock),
    )
    _thread_pool  = concurrent.futures.ThreadPoolExecutor(
        max_workers=SYNC_MAX_WORKERS, thread_name_prefix="sync-worker",
    )

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Interrupted — exiting.")
    finally:
        if _process_pool:
            _process_pool.shutdown(wait=False)
        if _thread_pool:
            _thread_pool.shutdown(wait=False)
