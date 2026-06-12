"""
Noderouter Python Runner — Tunnel Architecture
==============================================
Pure asyncio daemon. Establishes an outbound WebSocket tunnel to Go Core
and processes tasks over it:

  Sync Channel  →  req/res frames over the WebSocket tunnel  (< 5 s tasks)
  Async Channel →  PostgreSQL asyncpg LISTEN new_job + SKIP LOCKED claim
                   (long-running tasks; executed in isolated ProcessPoolExecutor)

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
import psycopg2
from psycopg2.pool import ThreadedConnectionPool
import websockets
from dotenv import load_dotenv

# ── Bootstrap ─────────────────────────────────────────────────────────────────
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [runner] %(levelname)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────────
def _resolve_core_ws_url() -> str:
    ws_url = os.getenv("CORE_WS_URL", "").strip()
    if ws_url:
        return ws_url

    core_url = os.getenv("CORE_URL", "").strip()
    if core_url:
        if core_url.startswith("http://"):
            return "ws://" + core_url[7:]
        if core_url.startswith("https://"):
            return "wss://" + core_url[8:]
        if core_url.startswith("ws://") or core_url.startswith("wss://"):
            return core_url
        return core_url

    return "ws://localhost:3000"


CORE_WS_URL       = _resolve_core_ws_url()
NODE_ID           = os.getenv("NODE_ID", "")
RUNNER_SECRET     = os.getenv("RUNNER_SECRET", "")
APPS_DIR          = os.getenv(
    "APPS_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "apps"),
)
DATABASE_URL      = os.getenv("DATABASE_URL", "")
ASYNC_MAX_WORKERS = int(os.getenv("ASYNC_MAX_WORKERS", "4"))
SYNC_MAX_WORKERS  = int(os.getenv("SYNC_MAX_WORKERS", "8"))

_HMAC_TS_HEADER  = "X-Noderouter-Ts"
_HMAC_SIG_HEADER = "X-Noderouter-Sig"

_IS_WINDOWS = platform.system() == "Windows"

# ── Shutdown Coordination ──────────────────────────────────────────────────────
# Declared here; initialised as asyncio.Event() inside main().
_shutdown_event: asyncio.Event

# ── Worker Pools ───────────────────────────────────────────────────────────────
# Initialised in __main__ guard to avoid Windows spawn recursion.
_process_pool: concurrent.futures.ProcessPoolExecutor | None = None
_thread_pool:  concurrent.futures.ThreadPoolExecutor  | None = None

# ── DB Pool (asyncpg) ─────────────────────────────────────────────────────────
_db_pool: asyncpg.Pool | None = None
_sync_db_pool: ThreadedConnectionPool | None = None

# ── App Registry ───────────────────────────────────────────────────────────────
_app_registry: dict = {}
_registry_lock = threading.Lock()   # sync lock — held only during writes in _load_app
_import_lock = threading.Lock()      # serialises app module imports in the daemon process
_conn_capable:  dict[int, bool] = {}

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


# ── HMAC Tunnel Signature ──────────────────────────────────────────────────────
def _compute_tunnel_sig(ts: str, node_id: str) -> str:
    """
    Compute the tunnel-handshake HMAC signature.
    Message scheme: "{timestamp}\\n{node_id}" — mirrors VerifyTunnelHandshake
    in middleware/hmac.go on the Go Core side.
    """
    message = f"{ts}\n{node_id}".encode()
    return "sha256=" + hmac_lib.new(
        RUNNER_SECRET.encode(), message, hashlib.sha256
    ).hexdigest()


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
    next _resolve_node_id() call to auto-register fresh rather than replaying
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


def _derive_core_http_url() -> str:
    """Convert the WS/WSS URL to HTTP/HTTPS for REST calls."""
    url = CORE_WS_URL
    if url.startswith("wss://"):
        return "https://" + url[6:]
    if url.startswith("ws://"):
        return "http://" + url[5:]
    return url


def _resolve_node_id() -> str:
    """
    Resolve NODE_ID through three layers (highest priority first):

    1. NODE_ID env var — set by the operator, takes unconditional precedence.
    2. Persisted file  — written on first successful auto-registration.
       Location: APPS_DIR/.node_id  (inside the shared apps volume, so it
       survives Docker container re-creates and process restarts alike).
    3. Auto-register   — POST /api/nodes/auto-register with HMAC body auth.
       Hostname is used as the node name (idempotent: same hostname → same id).
       Location type is detected automatically:
         • docker_internal  — /.dockerenv present (standard Docker marker)
         • localhost        — bare-metal / VM

    Updates the module-level NODE_ID global and returns it.
    Returns empty string if all three layers fail (tunnel loop will retry).
    """
    global NODE_ID

    # 1. Env var set by operator
    if NODE_ID:
        return NODE_ID

    # 2. Persisted file (per-hostname — safe when APPS_DIR is a shared volume)
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

    # 3. Auto-register via Core REST API
    import socket
    import urllib.error
    import urllib.request

    hostname    = os.getenv("HOSTNAME", socket.gethostname())
    location    = _detect_location()
    # runner_url is a stable per-machine identity used by Core to detect and
    # delete ghost nodes left behind after Docker container recreates (where
    # the hostname changes but the physical host is the same).
    # MUST be "runner://<hostname>" — unique per machine/container — NOT
    # CORE_WS_URL, which is identical across all runners and would cause Core's
    # ghost-cleanup query to delete sibling runner nodes by mistake.
    runner_url  = f"runner://{hostname}"
    body        = json.dumps({"name": hostname, "location_type": location, "runner_url": runner_url}).encode()
    base_url    = _derive_core_http_url()
    endpoint    = f"{base_url}/api/nodes/auto-register"

    for attempt in range(5):
        if attempt:
            delay = 2 * attempt
            log.info("[node-id] Retrying auto-register in %ds (attempt %d/5) …", delay, attempt + 1)
            time.sleep(delay)

        # Refresh HMAC timestamp on every attempt to stay within the 30 s replay window.
        ts          = str(int(time.time()))
        body_hash   = hashlib.sha256(body).hexdigest()
        message     = f"{ts}\n{body_hash}".encode()
        sig         = "sha256=" + hmac_lib.new(
            RUNNER_SECRET.encode(), message, hashlib.sha256,
        ).hexdigest()

        req = urllib.request.Request(
            endpoint,
            data=body,
            headers={
                "Content-Type":      "application/json",
                "X-Noderouter-Ts":   ts,
                "X-Noderouter-Sig":  sig,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data    = json.loads(resp.read())
                NODE_ID = data["node_id"]
                os.makedirs(APPS_DIR, exist_ok=True)
                with open(node_id_file, "w") as fh:
                    fh.write(NODE_ID)
                log.info(
                    "[node-id] Auto-registered: id=%s name=%s location=%s",
                    NODE_ID, hostname, location,
                )
                return NODE_ID
        except Exception as exc:
            log.warning("[node-id] Auto-register attempt %d/5 failed: %s", attempt + 1, exc)

    log.error(
        "[node-id] Auto-registration failed after 5 attempts — "
        "tunnel will connect without NODE_ID (async job routing disabled)"
    )
    return ""


# ── ZIP extraction helpers ─────────────────────────────────────────────────────
_MAX_EXTRACT_FILE_BYTES  = 50 * 1024 * 1024   # 50 MB per-file cap
_MAX_EXTRACT_TOTAL_BYTES = 500 * 1024 * 1024  # 500 MB aggregate cap


def _extract_zip_to_apps(app_name: str, zip_bytes: bytes) -> str:
    """
    Safely extract a ZIP bundle (raw bytes) into APPS_DIR/{app_name}/.

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

    accepts_conn = "conn" in inspect.signature(module.execute).parameters

    with _registry_lock:
        _app_registry[app_name] = module
    _conn_capable[id(module)] = accepts_conn
    log.info("App loaded: %s (%s) [conn-injection: %s]", app_name, app_path, accepts_conn)
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
    execute() so lazy imports inside app code resolve (F3). Uses short-lived
    psycopg2 connections for any DB writes per the Direct DB Write
    Architecture.
    """
    before = set(sys.modules)
    _purge_app_modules(app_name)
    try:
        module = _import_app_module(app_name, app_path)
        with _app_import_context(app_path):
            return module.execute(data)
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
    """Execute a sync app, injecting a pooled connection when supported."""
    fn = getattr(module, "execute")

    # F3: keep the app dir + libs/ importable across the call so lazy imports
    # inside execute() resolve.
    with _app_import_context(module.__file__):
        if _sync_db_pool is None or not _conn_capable.get(id(module), False):
            return fn(payload)

        conn = _sync_db_pool.getconn()
        try:
            with conn:
                return fn(payload, conn=conn)
        finally:
            with contextlib.suppress(Exception):
                _sync_db_pool.putconn(conn)


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
    if asyncio.iscoroutinefunction(fn):
        # F3: pin the app's import paths across await points; the ref-counted
        # context tolerates interleaved executions of other apps.
        with _app_import_context(module.__file__):
            return await fn(payload)
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_thread_pool, _run_sync_execute, module, payload)


# ── Sync request handler (tunnel req frame) ────────────────────────────────────
async def _handle_req(ws, msg: dict) -> None:
    """
    Handle a single synchronous req frame received from Core over the tunnel.

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
    rid      = msg.get("rid", "")
    app_name = msg.get("app", "")
    payload  = msg.get("payload") or {}

    # B11: catch serialization failures so Core's goroutine always gets a frame
    # back; previously a non-serializable result silently caused a 30 s timeout.
    async def _send_res(status: int, body: dict) -> None:
        try:
            frame = json.dumps({"type": "res", "rid": rid, "status": status, "body": body})
        except (TypeError, ValueError) as exc:
            log.error("Sync res serialization error rid=%s: %s", rid, exc)
            frame = json.dumps({
                "type": "res", "rid": rid, "status": 500,
                "body": {"error": "response serialization failed"},
            })
        try:
            await ws.send(frame)
        except Exception as exc:
            log.debug("Tunnel send failed rid=%s: %s", rid, exc)

    if err := _validate_app_name(app_name):
        await _send_res(400, {"error": err})
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
                    await _send_res(404, {"error": load_err})
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

        await _send_res(200, result if isinstance(result, dict) else {"result": result})

        # Send action frames to Core after the response is delivered so the
        # calling client is unblocked before we fire notifications.
        for act in actions_to_dispatch:
            if not isinstance(act, dict) or not act.get("name"):
                continue
            try:
                frame = json.dumps({
                    "type":        "action",
                    "app_name":    app_name,
                    "action_name": act["name"],
                    "payload":     act.get("payload"),
                })
                await ws.send(frame)
                log.debug("[action] Sent action frame: app=%s action=%s", app_name, act["name"])
            except Exception as exc:
                log.debug(
                    "[action] Frame send failed app=%s action=%s: %s",
                    app_name, act.get("name"), exc,
                )
    except Exception as exc:
        log.exception("Sync execute error: app=%s rid=%s", app_name, rid)
        await _send_res(500, {"error": str(exc)})


async def _handle_req_with_permit(ws, msg: dict) -> None:
    try:
        await _handle_req(ws, msg)
    finally:
        if _sync_semaphore is not None:
            _sync_semaphore.release()


# ── WebSocket Tunnel Loop ──────────────────────────────────────────────────────
async def _tunnel_loop() -> None:
    """
    Persistent outbound WebSocket tunnel to Go Core.
    Reconnects automatically using exponential backoff.

    Frame types (Core → Runner): hello, ping, req
    Frame types (Runner → Core): pong, res
    """
    attempt = 0
    uri = f"{CORE_WS_URL}/api/nodes/connect"

    while not _shutdown_event.is_set():
        try:
            ts = str(int(time.time()))
            headers = {
                "X-Node-ID":     NODE_ID,
                _HMAC_TS_HEADER: ts,
            }
            if RUNNER_SECRET and NODE_ID:
                headers[_HMAC_SIG_HEADER] = _compute_tunnel_sig(ts, NODE_ID)

            async with websockets.connect(uri, additional_headers=headers) as ws:
                attempt = 0
                log.info("[tunnel] Connected to core at %s", uri)

                async for raw in ws:
                    try:
                        msg = json.loads(raw)
                    except Exception:
                        continue

                    t = msg.get("type")
                    if t == "hello":
                        log.info("[tunnel] Hello from core: node_name=%s", msg.get("node_name"))
                    elif t == "ping":
                        await ws.send(json.dumps({"type": "pong"}))
                    elif t == "req":
                        if _sync_semaphore is None:
                            asyncio.create_task(_handle_req(ws, msg))
                            continue
                        await _sync_semaphore.acquire()
                        try:
                            asyncio.create_task(_handle_req_with_permit(ws, msg))
                        except Exception:
                            _sync_semaphore.release()
                            raise

        except asyncio.CancelledError:
            return
        except Exception as exc:
            # ── 401 / 403: Core rejected our node_id ─────────────────────────
            # This happens when the node record was deleted from Core's DB
            # (admin removal, DB wipe, disaster recovery). Clear the persisted
            # node_id and re-register so we get a fresh UUID.
            status_code = getattr(exc, "status_code", None)
            if status_code in (401, 403):
                log.warning(
                    "[tunnel] Core rejected node_id=%s (HTTP %d) — "
                    "clearing cached id and re-registering",
                    NODE_ID, status_code,
                )
                _clear_persisted_node_id()
                await asyncio.to_thread(_resolve_node_id)
                if NODE_ID:
                    log.info("[tunnel] Re-registered as node_id=%s — reconnecting now", NODE_ID)
                    attempt = 0  # reset backoff after successful re-registration
                else:
                    # Auto-registration failed (Core unreachable, bad secret, etc.).
                    # Back off before retrying so we don't hammer Core.
                    delay = _backoff(attempt)
                    log.error(
                        "[tunnel] Re-registration failed — backing off %.1fs", delay
                    )
                    attempt += 1
                    try:
                        await asyncio.wait_for(_shutdown_event.wait(), timeout=delay)
                    except asyncio.TimeoutError:
                        pass
                continue

            # ── All other errors: network drop, timeout, etc. ─────────────────
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


# ── PostgreSQL LISTEN Daemon (asyncpg) ─────────────────────────────────────────
async def _async_listener_loop() -> None:
    """
    Persistent PostgreSQL LISTEN daemon via asyncpg.
    Listens on new_job (trigger async job dispatch) and app_updated (hot-reload).
    Reconnects automatically with exponential backoff.
    """
    log.info("Async listener started — LISTEN new_job + app_updated (node_id: %s)", NODE_ID)
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

    while not _shutdown_event.is_set():
        conn = None
        try:
            conn = await asyncpg.connect(DATABASE_URL)
            await conn.add_listener("new_job",     _on_new_job)
            await conn.add_listener("app_updated", _on_app_updated)
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
    global _shutdown_event, _db_pool, _sync_db_pool, _sync_semaphore, _app_load_locks_mu
    _shutdown_event = asyncio.Event()

    # B9: initialise semaphore now that the event loop is running.
    # Capacity = SYNC_MAX_WORKERS × 4 → queue depth of 4× the thread pool size
    # before backpressure kicks in. Tasks that exceed this wait here rather than
    # spawning without bound and exhausting asyncio / OS resources.
    _sync_semaphore = asyncio.Semaphore(SYNC_MAX_WORKERS * 4)

    # B12: asyncio.Lock objects must be created inside the running event loop.
    _app_load_locks_mu = asyncio.Lock()

    loop = asyncio.get_running_loop()
    if not _IS_WINDOWS:
        loop.add_signal_handler(signal.SIGTERM, _shutdown_event.set)
        loop.add_signal_handler(signal.SIGINT,  _shutdown_event.set)
    # Windows: KeyboardInterrupt is caught at the asyncio.run() level below.

    log.info("=" * 60)
    log.info("Noderouter Python Runner — Tunnel Architecture")
    log.info("  Core WS URL  : %s", CORE_WS_URL)
    log.info("  Node ID      : %s", NODE_ID or "(resolving…)")
    log.info("  Apps         : %s", APPS_DIR)
    log.info("  Async Chan   : %s", "enabled" if DATABASE_URL else "disabled (DATABASE_URL not set)")
    log.info("  Async Workers: %d", ASYNC_MAX_WORKERS)
    log.info("  Sync Workers : %d", SYNC_MAX_WORKERS)
    log.info("=" * 60)

    # Resolve NODE_ID: env var → persisted file → auto-register with Core.
    # Must run after app preload so APPS_DIR exists for the .node_id file.
    await asyncio.to_thread(_resolve_node_id)
    if NODE_ID:
        log.info("  Node ID      : %s (resolved)", NODE_ID)

    # Preload apps synchronously before accepting any tunnel requests.
    await asyncio.to_thread(_preload_apps)

    if DATABASE_URL:
        try:
            _sync_db_pool = ThreadedConnectionPool(
                2,
                max(SYNC_MAX_WORKERS, ASYNC_MAX_WORKERS) + 4,
                dsn=DATABASE_URL,
            )
            log.info(
                "psycopg2 threaded pool initialized (min=2, max=%d)",
                max(SYNC_MAX_WORKERS, ASYNC_MAX_WORKERS) + 4,
            )
        except Exception as exc:
            _sync_db_pool = None
            log.warning("psycopg2 threaded pool initialization failed: %s", exc)

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

    if _db_pool:
        await _db_pool.close()
    if _sync_db_pool:
        _sync_db_pool.closeall()
        _sync_db_pool = None
    if _process_pool:
        _process_pool.shutdown(wait=False)
    if _thread_pool:
        _thread_pool.shutdown(wait=False)


if __name__ == "__main__":
    if not RUNNER_SECRET:
        log.warning("RUNNER_SECRET is not set — HMAC auth disabled (dev mode only)")

    # Initialise executor pools before asyncio.run() to avoid Windows spawn recursion:
    # ProcessPoolExecutor uses 'spawn' on Windows, which re-imports this module in
    # every subprocess — module-level pool creation would cause infinite spawning.
    _process_pool = concurrent.futures.ProcessPoolExecutor(max_workers=ASYNC_MAX_WORKERS)
    _thread_pool  = concurrent.futures.ThreadPoolExecutor(
        max_workers=SYNC_MAX_WORKERS, thread_name_prefix="sync-worker",
    )

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Interrupted — exiting.")
    finally:
        if _sync_db_pool:
            _sync_db_pool.closeall()
        if _process_pool:
            _process_pool.shutdown(wait=False)
        if _thread_pool:
            _thread_pool.shutdown(wait=False)
