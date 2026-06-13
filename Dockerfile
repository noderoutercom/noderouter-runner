# ── Stage 1: Build wheels for packages with C extensions ─────────────────────
FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY requirements.txt .

# Build wheels into a local cache so the runtime stage can install offline
RUN pip install --upgrade pip \
    && pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim

# libpq5: runtime shared library required by psycopg2-binary
# (binary wheel bundles libpq but still links against the system libpq5 on some builds)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install from pre-built wheels — no compiler needed in the runtime image
COPY --from=builder /wheels /wheels
COPY requirements.txt .
RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt \
    && rm -rf /wheels

# Copy runner source + generated protobuf stubs
COPY runner.py tunnel_pb2.py tunnel_pb2_grpc.py ./

# Pre-create the apps directory; typically mounted as a shared volume
RUN mkdir -p /apps

# Non-root runtime user
RUN useradd -r -s /bin/false runner \
    && chown -R runner:runner /app /apps

USER runner

# Env defaults — override at runtime via docker-compose / --env-file
ENV APPS_DIR=/apps \
    ASYNC_MAX_WORKERS=4 \
    SYNC_MAX_WORKERS=8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# The runner dials Go Core outbound over gRPC mTLS; no inbound port is needed.

ENTRYPOINT ["python", "-u", "runner.py"]
