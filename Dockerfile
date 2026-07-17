# ============================================================
# LogSentry SIEM — Multi-Stage Production Dockerfile
# ============================================================
#
# Stage 1: builder  — installs dependencies, no source code
# Stage 2: runtime  — minimal image, non-root user, no build tools
#
# Build:  docker build -t logsentry:latest .
# Run:    docker run -p 8000:8000 --env-file .env logsentry:latest
# ============================================================

# ---- Stage 1: Dependency Builder ----
FROM python:3.11-slim AS builder

# Prevent .pyc files and enable unbuffered stdout for log streaming
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Install only the system libs needed to compile Python packages
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies into an isolated prefix
COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install --prefix=/install --no-cache-dir -r requirements.txt


# ---- Stage 2: Runtime ----
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    # Prevent Python from buffering log output
    PYTHONFAULTHANDLER=1

WORKDIR /app

# Install only the shared libs required at runtime (no compiler)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpq5 \
        curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder stage
COPY --from=builder /install /usr/local

# Create a non-root user for runtime
RUN groupadd --gid 1001 logsentry \
    && useradd --uid 1001 --gid logsentry --shell /bin/sh --create-home logsentry \
    && mkdir -p /app/logs \
    && chown -R logsentry:logsentry /app

# Copy application source code
COPY --chown=logsentry:logsentry . .

# Drop privileges
USER logsentry

# Expose API port
EXPOSE 8000

# Health check — uses the /liveness probe (no dependencies, always fast)
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/liveness || exit 1

# Production-grade entrypoint:
#   --workers 4        → 4 sync Uvicorn workers (tune via WEB_CONCURRENCY env var)
#   --proxy-headers    → trust X-Forwarded-For from reverse proxy
#   --forwarded-allow-ips=* → allow proxy header from any upstream IP (scope if needed)
#   --access-log       → structured access log to stdout
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "4", \
     "--proxy-headers", \
     "--forwarded-allow-ips=*", \
     "--access-log"]
