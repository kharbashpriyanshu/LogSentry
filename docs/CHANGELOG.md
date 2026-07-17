# Changelog

All notable changes to LogSentry are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [1.0.0] — Sprint 9 — 2026-07-17

### Added — S.H.I.E.L.D. Integration & Final Release
- **S.H.I.E.L.D. Platform Architecture**: Positioned LogSentry as the flagship Log Analysis module. Documented cross-module integration (`docs/PLATFORM_ARCHITECTURE.md`).
- **Demo Dataset**: Added realistic, safe sample logs (Apache, Nginx, attack vectors) and JSON alert payloads in `sample_data/`.
- **Demo Script**: Created `docs/DEMO.md` for end-to-end interview/presentation walkthroughs.
- **Portfolio Readiness**: Added `docs/PORTFOLIO.md` detailing motivation, engineering challenges, architecture decisions, and lessons learned.
- **README Overhaul**: Completely rewrote `README.md` for open-source public release, including architecture diagrams, badges, and screenshot placeholders.
- **Repository Polish**: Final repository review ensuring consistent naming, imports, type hints, and removal of dead code/TODOs.

---

## [0.8.0] — Sprint 8 — 2026-07-17

### Added — Production Hardening
- **Structured JSON logging** (`StructuredFormatter`): every log line is a parseable JSON object with timestamp, level, logger, message, correlation_id, module, function, and line number.
- **Sensitive field scrubbing**: `api_key`, `password`, `token`, `secret`, `authorization`, `key` are automatically redacted from log output.
- **Full security header suite**: CSP, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, HSTS (with preload), Referrer-Policy, Permissions-Policy.
- **RequestSizeLimitMiddleware**: rejects oversized request bodies (default 1 MB) with HTTP 413 before any parsing occurs.
- **File upload hardening**: filename sanitisation (path traversal protection), content-type allowlist, configurable size cap (default 10 MB).
- **Settings validators**: ENVIRONMENT, LOG_LEVEL, AI_PROVIDER, confidence range, temperature range validated at startup (fail-fast).
- **Thread-safe LRU cache**: `InMemoryCache` now uses `threading.Lock` + `OrderedDict` with configurable max-entries and LRU eviction.
- **Observability endpoints**: `/metrics`, `/liveness`, `/readiness`, `/version`, `/health/live`, `/health/ready`.
- **In-process metrics**: request total, failure count, average latency, status code distribution.
- **Multi-stage Dockerfile**: builder stage with GCC, runtime stage without build tools, non-root user (uid 1001), HEALTHCHECK.
- **Production docker-compose**: service health dependencies, postgres on `127.0.0.1` only, named bridge network, persistent logs volume, `no-new-privileges` security option.
- **Expanded CI/CD**: 4-job pipeline (quality, test, docker, summary) with Bandit, pip-audit, coverage threshold enforcement, Docker build smoke tests.
- **`tests/test_hardening.py`**: 41 new tests covering security headers, observability, request limits, file security, cache thread-safety, formatter, and settings validators.
- **`docs/SECURITY.md`**: vulnerability reporting policy and security architecture overview.
- **`docs/DEPLOYMENT.md`**: Docker, production checklist, nginx reverse proxy example, Kubernetes probes, scaling guidance.
- **`docs/CONTRIBUTING.md`**: development setup, code standards, architecture principles, PR process.
- **`docs/CHANGELOG.md`**: this file.
- **Strict CORS**: replaced `allow_origins=["*"]` with configurable allowlist; restricted methods to `GET`, `POST`, `OPTIONS`.
- **Docs hidden in production**: Swagger UI, ReDoc, and OpenAPI schema are disabled when `ENVIRONMENT=production`.
- **`ReportingError` handlers**: all 6 reporting exceptions now registered in global exception handlers.

### Changed
- `CoreMiddleware`: f-string logs replaced with structured `extra={}` logging; added real client IP extraction (`X-Forwarded-For`); metrics integrated.
- `Settings`: added `VERSION`, `MAX_REQUEST_SIZE_BYTES`, `MAX_UPLOAD_SIZE_BYTES`, `CORS_ALLOWED_ORIGINS`, `RATE_LIMIT_RPM`; removed unused `LOG_ROTATION`/`LOG_RETENTION` fields.
- `ParsingService`: SRP refactor — `parse_uploaded(path)` separates file I/O from parsing; `parse_file(UploadFile)` kept as backward-compat shim.
- `HealthResponse`: extended with `environment`, `version`, `subsystems` fields.
- `main.py`: migrated from deprecated `@app.on_event` to `@asynccontextmanager lifespan`.
- `requirements.txt`: all packages updated to current stable versions.
- `requirements-dev.txt`: added `bandit>=1.7.8`, `pip-audit>=2.7.3`.
- `pyproject.toml`: added `S`, `UP`, `N` ruff rules; bandit config; coverage omit/exclude; mypy exclude for frontend.

---

## [0.7.0] — Sprint 7 — 2026-07-17
- Reporting & Incident Management Engine
- ExecutiveReport, TechnicalReport, IncidentReport models
- TimelineEngine (6-stage pipeline)
- PDFGenerator (reportlab), CSVGenerator, JSONGenerator
- POST /api/v1/reports/generate + export endpoints
- 34 tests, all passing

## [0.6.0] — Sprint 6 — 2026-07-17
- Interactive SOC Dashboard (React/TypeScript frontend)
- TanStack Query, Chart.js integration

## [0.5.0] — Sprint 5 — 2026-07-17
- Threat Intelligence Integration (AbuseIPDB, OTX, MITRE)
- EnrichmentService with TTL cache

## [0.4.0] — Sprint 4 — 2026-07-17
- AI SOC Analyst module
- OpenAI, Gemini, Ollama provider support
- Structured AI analysis responses

## [0.3.0] — Sprint 3 — 2026-07-17
- FastAPI REST API backend
- Correlation ID middleware
- Exception handler framework

## [0.2.0] — Sprint 2 — 2026-07-17
- Detection Engine with 6 rule types (SQLi, XSS, Path Traversal, CMDi, DirEnum, Brute Force)
- MITRE ATT&CK mapping

## [0.1.0] — Sprint 1 — 2026-07-17
- Core Log Parsing Engine (Apache, Nginx, Regex parsers)

## [0.0.1] — Sprint 0 — 2026-07-17
- Project foundation: FastAPI scaffold, Docker, CI, pre-commit
