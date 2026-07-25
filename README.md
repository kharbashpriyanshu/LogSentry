# LogSentry

AI-assisted Security Information and Event Management platform for log ingestion, threat detection, incident investigation and security analytics.

## Overview
LogSentry is a high-performance SIEM designed for modern SOC teams. It ingests raw security logs, automatically detects cyber attacks using strict rule engines, enriches indicators of compromise (IOCs) with real-time threat intelligence, runs AI-driven incident analysis for triage, and surfaces actionable data via a real-time React dashboard.

## Key Capabilities
- **Apache/Nginx log ingestion**
- **Log parsing and normalization**
- **SQL Injection detection**
- **XSS detection**
- **Path Traversal detection**
- **Command Injection detection**
- **Directory Enumeration detection**
- **Brute Force detection**
- **Alert lifecycle management**
- **Incident management**
- **Threat Intelligence enrichment** (AbuseIPDB, OTX, MITRE ATT&CK)
- **AI-assisted SOC analysis** (OpenAI, Gemini, Ollama)
- **Real-time WebSocket updates**
- **Reporting** (PDF, CSV, JSON Executive & Technical exports)
- **System health monitoring**
- **PostgreSQL persistence**
- **Alembic migrations**
- **React SOC dashboard**

## Architecture

```mermaid
graph TD
    User([User / Browser])
    Nginx[Nginx Reverse Proxy]
    React[React Dashboard]
    API[FastAPI REST/WebSocket API]
    DB[(PostgreSQL)]

    User -->|HTTPS| Nginx
    Nginx -->|Static Assets| React
    Nginx -->|/api/ Proxy| API
    
    subgraph Services
        Parsing[Parsing Engine]
        Detection[Detection Engine]
        Incident[Incident Management]
        AI[AI Analysis]
        Threat[Threat Intelligence]
        Reporting[Reporting]
    end

    API --> Services
    Services -->|SQLAlchemy| DB

    AI -->|External API| LLM[OpenAI / Gemini / Ollama]
    Threat -->|External API| AbuseIPDB[AbuseIPDB / OTX]
```

## Detection Pipeline
The detection flow processes raw strings into actionable security intelligence:
1. **Log Input:** Raw logs are ingested via file upload or stream.
2. **Parser:** The string is parsed and normalized into standard fields (IP, Timestamp, Endpoint, etc.).
3. **Detection Engine:** The normalized event passes through the Rule Registry.
4. **Rule Match:** Specific attack classes (e.g., SQLi, XSS, Path Traversal, Command Injection) are detected using RegEx constraints or temporal correlation (Brute Force).
5. **Alert & Persistence:** A high-confidence Alert is generated and saved to PostgreSQL.
6. **Event Publication:** The new record triggers a database commit and subsequent WebSocket broadcast.
7. **Dashboard:** The SOC analyst sees the alert instantly on the React dashboard.

## Technology Stack

**Backend**
- Python 3.11+
- FastAPI
- Pydantic v2
- SQLAlchemy
- Alembic

**Database**
- PostgreSQL

**Frontend**
- React
- TypeScript
- Vite
- Tailwind CSS
- TanStack Query (React Query)
- Lucide React

**Infrastructure**
- Docker
- Docker Compose
- Nginx

**Testing**
- Pytest

**Security/Intelligence**
- AbuseIPDB
- AlienVault OTX
- MITRE ATT&CK mapping
- Configurable AI Providers (OpenAI, Gemini, Ollama)

## Screenshots
Screenshots of the fully integrated LogSentry SIEM platform:

### 1. Unified Dashboard
![LogSentry Dashboard](docs/images/dashboard.png)

### 2. Incident & Alert Management
![Alert Triage](docs/images/alerts.png)
![Incident Details](docs/images/alert-details.png)

### 3. System Health & Infrastructure
![System Health](docs/images/system-health.png)

### 4. Real-time Threat Intelligence
![Threat Intelligence Enrichment](docs/images/threat-intel.png)

### 5. Automated Reporting Engine
![Incident Reporting](docs/images/reports.png)

*(Note: The AI Analysis module screenshot is currently not displayed in this demo due to missing provider configuration during the automated capture.)*
## Security Architecture
LogSentry implements strict production security controls:
- **Production fail-fast configuration:** Will not start in `production` without explicitly setting `DATABASE_URI`.
- **Restricted CORS:** Configurable allowed origins.
- **Security Headers:** Strict deployment of `CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy` via middleware and Nginx.
- **Upload validation:** Explicit request-size limits to prevent buffer overflow or DoS attacks.
- **Non-public PostgreSQL:** PostgreSQL is bound only to the internal Docker network in `docker-compose.prod.yml`.

## Project Structure
```text
logsentry/
├── app/                  # FastAPI Application Code
│   ├── api/              # REST Endpoints and WebSockets
│   ├── detection/        # Security Rules Engine
│   ├── models/           # SQLAlchemy DB Models
│   ├── services/         # Core Business Logic
│   └── ...
├── frontend/             # React SPA
│   ├── src/pages/        # Dashboard Views
│   ├── Dockerfile        # Nginx Production Build
│   └── nginx.conf        # Proxy & Security Config
├── tests/                # Pytest Test Suite
├── alembic/              # Database Migrations
├── docs/                 # Platform Documentation
├── DEPLOYMENT.md         # Deployment Guide
└── docker-compose.*      # Container Orchestration
```

## Local Development
1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/logsentry.git
   cd logsentry
   ```
2. **Environment Configuration:**
   Copy `.env.example` to `.env` and fill in dummy API keys for local testing.
3. **Backend Startup:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt -r requirements-dev.txt
   alembic upgrade head
   uvicorn app.main:app --reload
   ```
4. **Frontend Startup:**
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

## Production Deployment
Please see [DEPLOYMENT.md](DEPLOYMENT.md) for full instructions.
Production deployment utilizes a multi-container Docker Compose stack comprising PostgreSQL, the FastAPI backend, and an Nginx reverse proxy serving the production React build. 

## API Documentation
When running locally, automatic interactive API documentation is available at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## Testing
The backend test suite leverages Pytest to ensure reliability.
- **Backend Tests:** 127 passing tests
- **Coverage:** 84.14%

To run the test suite:
```bash
pytest tests/ --cov=app
```

## Production Status
**Release Candidate Status:** `Production Deployment Ready With Warnings`

Verified features:
- Backend test suite
- Frontend production compilation
- Configuration fail-fast behavior
- Persistence logic through automated tests
- Security controls through tests/code inspection

Pending environment-level verification:
- Live PostgreSQL deployment orchestration
- Docker Compose orchestration execution
- Nginx runtime routing
- Container restart persistence
- WebSocket behavior through production Nginx

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact & Documentation
Detailed audit and technical reports can be found in `docs/audits/`. For contributing guidelines or security vulnerability reporting, please see `CONTRIBUTING.md` and `SECURITY.md`.
