# =============================================================================
# E-WITNESS Production Multi-Stage Hardened Dockerfile
# Phase 108: Container & Supply-Chain Security Hardening
#
# Security Controls:
# - Multi-stage build with build tool isolation
# - Minimal unprivileged non-root execution (UID 10001, GID 10001)
# - No hardcoded secrets or environment variables
# - Read-only filesystem friendly with bounded temporary directory
# - Hardened Python runtime flags (no bytecode writing in runtime, unbuffered)
# - Strict health check using Python standard library without curl/wget dependencies
# =============================================================================

# --- Stage 1: Build & Dependency Wheel Builder ---
FROM python:3.13-slim-bookworm AS builder

# Prevent interactive debconf prompts and install build tools
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN python -m pip install --upgrade pip setuptools wheel && \
    python -m pip wheel --no-cache-dir --wheel-dir /build/wheels -r requirements.txt

# --- Stage 2: Hardened Unprivileged Production Runtime ---
FROM python:3.13-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PORT=8000

# Install runtime shared libraries (libpq for asyncpg/postgresql)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged application user and group
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -d /app -M appuser

WORKDIR /app

# Copy pre-built wheels from builder stage and install
COPY --from=builder /build/wheels /tmp/wheels
COPY requirements.txt /app/requirements.txt
RUN python -m pip install --no-cache-dir --no-index --find-links=/tmp/wheels -r /app/requirements.txt && \
    rm -rf /tmp/wheels

# Copy application source code
COPY backend /app/backend
COPY ai_services /app/ai_services
COPY alembic.ini /app/alembic.ini

# Set permissions: appuser owns /app, read-only application code
RUN chown -R appuser:appgroup /app && \
    chmod -R 550 /app && \
    chmod -R 770 /app/backend/app/infrastructure

# Create temporary directory for runtime scratch operations
RUN mkdir -p /tmp/ewitness && chown -R appuser:appgroup /tmp/ewitness && chmod 700 /tmp/ewitness

USER 10001:10001

EXPOSE 8000

# Standardized container health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health').read()" || exit 1

ENTRYPOINT ["python", "-m", "uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
