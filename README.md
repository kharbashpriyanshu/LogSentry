# LogSentry SIEM (v1.0.0) 🛡️

> **Enterprise-grade Security Information and Event Management platform.**
> The flagship Log Analysis module of the S.H.I.E.L.D. cybersecurity ecosystem.

[![CI](https://github.com/your-org/logsentry/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/logsentry/actions)
[![Coverage](https://codecov.io/gh/your-org/logsentry/branch/main/graph/badge.svg)](https://codecov.io/gh/your-org/logsentry)
[![Python](https://img.shields.io/badge/python-3.11+-blue)](https://python.org)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](Dockerfile)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📖 Overview

LogSentry is a modular, high-performance SIEM platform built for modern SOC teams. It ingests raw security logs, detects attacks via a strict rule registry, enriches indicators of compromise (IOCs) with real-time threat intelligence, runs AI-driven incident analysis, and generates professional PDF/CSV incident reports.

LogSentry is designed using **Clean Architecture** and **SOLID principles**, making it highly extensible and production-ready.

![Dashboard Placeholder](docs/assets/dashboard_placeholder.png)  
*(Screenshot: LogSentry SOC Dashboard)*

---

## ✨ Features

- **Log Parsing Engine:** Extensible parsers for Apache, Nginx, and custom Regex with safe file upload handling.
- **Detection Engine:** Pluggable rule registry (SQLi, XSS, Path Traversal, CMDi, Dir Enum, Brute Force) mapped to MITRE ATT&CK.
- **AI SOC Analyst:** Provider-agnostic LLM analysis (OpenAI, Gemini, Ollama) for automated triage and false-positive reduction.
- **Threat Intelligence:** Built-in enrichment via AbuseIPDB and OTX AlienVault, backed by a thread-safe LRU cache.
- **Incident Reporting:** 6-stage chronological Timeline Engine generating Executive, Technical, and Incident reports (PDF, CSV, JSON).
- **Production Security:** Strict CORS, 7-header security suite (CSP, HSTS), 1MB request size cap, and JSON-Lines structured logging with auto-redaction.

---

## 🏗️ Architecture

LogSentry utilizes a decoupled, dependency-injected architecture to ensure testability and scalability.

```text
HTTP Request → Size Cap Middleware → Security Middleware → Thin API Router
                                                              │
                                                        DI Container
                                                              │
    ┌────────────────┬───────────────────┬────────────────────┴────────────────┐
    │                │                   │                                     │
 Parsing          Detection       Threat Intel                             Reporting
 Service          Service           Service                                 Service
    │                │                   │                                     │
(Regex/Nginx)  (Rule Registry)   (AbuseIPDB/OTX/Cache)   (Timeline Engine → PDF/CSV Gen)
```
See [PLATFORM_ARCHITECTURE.md](docs/PLATFORM_ARCHITECTURE.md) for details on how LogSentry integrates into the S.H.I.E.L.D. ecosystem.

---

## 🚀 Quick Start

### 1. Local Development
```bash
git clone https://github.com/your-org/logsentry.git
cd logsentry

# Setup Environment
cp .env.example .env
# Edit .env with your API keys (OpenAI, AbuseIPDB)

# Install Dependencies
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

# Run Server
uvicorn app.main:app --reload
```
API Documentation available at: `http://localhost:8000/docs`

### 2. Docker Deployment
```bash
# Start API and PostgreSQL
docker-compose up -d

# Verify Health
curl http://localhost:8000/api/v1/health
```

---

## 📚 Documentation Directory

| Category | Document | Description |
|----------|----------|-------------|
| **Core** | [PLATFORM_ARCHITECTURE.md](docs/PLATFORM_ARCHITECTURE.md) | S.H.I.E.L.D. integration & data flow |
| **Engine** | [DETECTION_ENGINE.md](docs/DETECTION_ENGINE.md) | How to write and add detection rules |
| **Engine** | [AI_SOC_ANALYST.md](docs/AI_SOC_ANALYST.md) | AI prompting and integration guides |
| **Engine** | [REPORTING.md](docs/REPORTING.md) | Timeline engine and export formats |
| **Ops** | [DEPLOYMENT.md](docs/DEPLOYMENT.md) | Docker, nginx, and Kubernetes guides |
| **Ops** | [SECURITY.md](docs/SECURITY.md) | Security policy and vulnerability disclosure |
| **Misc** | [DEMO.md](docs/DEMO.md) | Step-by-step interview walkthrough script |
| **Misc** | [PORTFOLIO.md](docs/PORTFOLIO.md) | Engineering challenges and design decisions |

---

## 📸 Screenshots

| Threat Intelligence | AI Analysis | Generated PDF Report |
|:---:|:---:|:---:|
| ![Threat Intel](docs/assets/intel_placeholder.png) | ![AI Analyst](docs/assets/ai_placeholder.png) | ![PDF Report](docs/assets/report_placeholder.png) |

---

## 🛠️ Technology Stack

- **Backend:** Python 3.11+, FastAPI, Pydantic v2
- **Frontend (Dashboard):** React, TypeScript, Vite, TailwindCSS
- **Storage & Caching:** PostgreSQL, Thread-safe In-Memory LRU Cache
- **AI & Intel:** OpenAI/Gemini SDKs, `httpx` for AbuseIPDB/OTX
- **Tooling:** Docker, GitHub Actions, Pytest, Ruff, Black, MyPy, Bandit

---

## 🤝 Contributing

We welcome contributions! Please review our [Contributing Guidelines](docs/CONTRIBUTING.md) before submitting a PR.
Code must pass all formatting, type-checking, and maintain **>65% test coverage**.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
