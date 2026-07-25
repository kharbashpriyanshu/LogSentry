# LogSentry Production Deployment

## Architecture
LogSentry is designed to be deployed as a multi-container Docker application using `docker-compose`. 

The architecture consists of three core components:
1. **Frontend / Reverse Proxy:** An Nginx container serving the compiled React single-page application (SPA) and acting as a reverse proxy for the backend API and WebSocket connections.
2. **Backend API:** A FastAPI application running via Uvicorn, serving the REST API and WebSocket events.
3. **Database:** A PostgreSQL 15 container for persistent storage of alerts, incidents, and threat intelligence.

## Prerequisites
- Docker and Docker Compose installed on the host machine.
- Minimum 2GB RAM and 2 CPUs recommended.
- Outbound internet access for Threat Intelligence (AbuseIPDB, OTX, MITRE) and AI integrations (OpenAI/Gemini).

## Required Environment Variables
A `.env.example` file is provided in the repository. Before deploying, you must create a `.env` file in the root directory.

Mandatory variables for production include:
- `ENVIRONMENT=production`
- `DATABASE_URI`: Must be explicitly set (e.g., `postgresql://user:password@db:5432/logsentry_db`).
- `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`
- `CORS_ALLOWED_ORIGINS`: Comma-separated list of allowed origins (e.g., `["https://logsentry.yourdomain.com"]`).
- `AI_PROVIDER` and corresponding API keys (e.g., `OPENAI_API_KEY`).
- `ABUSEIPDB_API_KEY`

## Secret Management
- **Never commit `.env` to version control.** The repository includes an updated `.gitignore` to prevent this.
- Ensure that `POSTGRES_PASSWORD` is changed from the default `postgres`.
- Do not expose `db` ports to the public internet. Ensure the `docker-compose.prod.yml` restricts PostgreSQL access to the internal Docker network.

## PostgreSQL Setup
The `db` service in `docker-compose.yml` automatically initializes the PostgreSQL database on first startup using the `POSTGRES_DB` and `POSTGRES_USER` environment variables. Data is persisted to the `postgres_data` Docker volume.

## Alembic Migrations
The database schema is managed via Alembic. On first run, you must apply the initial schema:
```bash
docker-compose exec api alembic upgrade head
```

## Docker Deployment
1. Build the production images and start the stack in detached mode:
```bash
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```
2. Verify the containers are running:
```bash
docker-compose ps
```

## Startup
The backend container includes a health check that waits for the `/liveness` endpoint to return HTTP 200. Nginx will automatically route traffic to the backend once it is healthy.

## Shutdown
To safely stop the application without losing data:
```bash
docker-compose down
```
Data will remain persisted in the `postgres_data` volume.

## Health Checks
- **Liveness:** `http://<host>/api/v1/health/live` (Checks if the process is running).
- **Readiness:** `http://<host>/api/v1/health/ready` (Checks if log parsers, detection rules, and the database are ready).
- **Detailed Health:** `http://<host>/api/v1/health` (Provides subsystem status).

## WebSocket Verification
WebSockets are exposed at `ws://<host>/api/v1/dashboard/ws/events`. Nginx handles the HTTP `Upgrade` header automatically. To verify, open the LogSentry Dashboard and observe real-time events appearing without page refreshes.

## Backup Considerations
- Backup the PostgreSQL database regularly using `pg_dump`:
```bash
docker-compose exec db pg_dump -U <user> <db_name> > backup.sql
```
- Backup the `logsentry_logs` volume if file-based logs are required for auditing.

## Updating LogSentry
To update to a new version:
1. Pull the latest code.
2. Run `docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build` to rebuild the images.
3. Run `docker-compose exec api alembic upgrade head` to apply any new database migrations.

## Rollback Procedure
1. Revert to the previous Git commit.
2. Run `docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build`.
3. If database migrations were applied, you may need to downgrade manually: `docker-compose exec api alembic downgrade <revision>`.

## Troubleshooting
- **Cannot connect to database:** Check if the `db` container is running and verify the `DATABASE_URI` in `.env`.
- **WebSocket connection failed:** Ensure Nginx is configured to pass the `Upgrade` header. Check browser console for CORS errors.
- **AI/Threat Intel not working:** Verify outbound internet connectivity from the `api` container and check API key validity in `.env`.
