# Deployment Guide

## Prerequisites

| Requirement | Minimum Version | Notes |
|-------------|----------------|-------|
| Python | 3.11+ | 3.12 recommended |
| Docker | 24.0+ | For containerised deployment |
| Docker Compose | 2.20+ | |
| PostgreSQL | 15+ | Managed DB recommended in production |

---

## Quick Start (Local Development)

```bash
# 1. Clone and enter the repository
git clone https://github.com/your-org/logsentry.git
cd logsentry

# 2. Create environment file
cp .env.example .env
# Edit .env with your API keys and database credentials

# 3. Create virtual environment
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate

# 4. Install dependencies
pip install -r requirements-dev.txt

# 5. Run the API server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

API docs: http://localhost:8000/docs

---

## Docker Deployment

### Build and Run

```bash
# Build the multi-stage image
docker build -t logsentry:latest .

# Run with environment variables
docker run -d \
  --name logsentry \
  -p 8000:8000 \
  --env-file .env \
  logsentry:latest
```

### Docker Compose (Recommended)

```bash
# Start all services (API + PostgreSQL)
docker-compose up -d

# Check health
docker-compose ps
docker-compose logs api --tail=50

# Stop
docker-compose down
```

### Verify Deployment

```bash
# Liveness probe
curl http://localhost:8000/liveness

# Readiness probe (checks subsystems)
curl http://localhost:8000/readiness

# Application version
curl http://localhost:8000/version

# Full health check
curl http://localhost:8000/api/v1/health
```

---

## Production Checklist

### Required Before Go-Live

- [ ] Set `ENVIRONMENT=production` in `.env`
- [ ] Set a strong `POSTGRES_PASSWORD` (not `postgres`)
- [ ] Set `DATABASE_URI` to your managed database connection string
- [ ] Configure `CORS_ALLOWED_ORIGINS` with your actual frontend domain(s)
- [ ] Set `OPENAI_API_KEY` or `GEMINI_API_KEY` for AI analysis
- [ ] Configure `ABUSEIPDB_API_KEY` and `OTX_API_KEY` for threat intelligence
- [ ] Place LogSentry behind a reverse proxy (nginx/traefik/Caddy) for TLS
- [ ] Set up log rotation for `/app/logs/`
- [ ] Configure firewall: only expose port 443 (reverse proxy) — not 8000 directly
- [ ] Enable monitoring for `/readiness` and `/metrics` endpoints

### Recommended

- [ ] Use a secrets manager (Vault, AWS Secrets Manager) instead of `.env` files
- [ ] Enable database connection pooling (PgBouncer)
- [ ] Set up alerting on `/readiness` returning non-200
- [ ] Configure Syslog or log shipping to your SIEM aggregator

---

## Environment Variables Reference

See `.env.example` for the full list with descriptions.

| Variable | Required in Production | Default |
|----------|----------------------|---------|
| `ENVIRONMENT` | Yes (`production`) | `development` |
| `DATABASE_URI` | Yes | None |
| `POSTGRES_PASSWORD` | Yes (strong value) | `postgres` |
| `CORS_ALLOWED_ORIGINS` | Yes | `["http://localhost:5173"]` |
| `OPENAI_API_KEY` | If using OpenAI | None |
| `GEMINI_API_KEY` | If using Gemini | None |
| `ABUSEIPDB_API_KEY` | Recommended | None |
| `OTX_API_KEY` | Recommended | None |

---

## Reverse Proxy Example (nginx)

```nginx
server {
    listen 443 ssl http2;
    server_name logsentry.your-org.com;

    ssl_certificate     /etc/letsencrypt/live/logsentry.your-org.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/logsentry.your-org.com/privkey.pem;

    # Forward to LogSentry API
    location / {
        proxy_pass         http://127.0.0.1:8000;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;

        # Size limit at proxy layer (belt-and-suspenders with app-level limit)
        client_max_body_size 10m;
    }
}
```

---

## Kubernetes (Helm — Sprint 9+)

Kubernetes manifests and a Helm chart are planned for Sprint 9. The application already provides standard Kubernetes-compatible health probes:

- **Liveness**: `GET /liveness`
- **Readiness**: `GET /readiness`

Example probe configuration:

```yaml
livenessProbe:
  httpGet:
    path: /liveness
    port: 8000
  initialDelaySeconds: 15
  periodSeconds: 30

readinessProbe:
  httpGet:
    path: /readiness
    port: 8000
  initialDelaySeconds: 10
  periodSeconds: 10
```

---

## Scaling

LogSentry uses synchronous FastAPI workers (default 4 via Uvicorn). For higher throughput:

1. **Horizontal scaling**: Run multiple containers behind a load balancer.
2. **Worker tuning**: Set `WEB_CONCURRENCY` environment variable to increase Uvicorn workers.
3. **Async migration**: AI and enrichment HTTP calls can be moved to async endpoints in Sprint 9.
4. **Cache**: The enrichment `InMemoryCache` is per-process. Replace with Redis for multi-instance deployments.
