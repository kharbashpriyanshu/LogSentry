# LogSentry Demo Walkthrough

This script is designed for technical interviews or presentations to showcase the end-to-end capabilities of LogSentry v1.0.0.

## Prerequisites
- Docker and Docker Compose installed.
- Valid API keys in `.env` (OpenAI, AbuseIPDB, OTX).
- Terminal open in the project root.

---

## Step 1: System Startup & Health

**Action:** Start the application stack.
```bash
docker-compose up -d
```
**Talking Point:** "LogSentry runs as a containerized microservice, currently backed by PostgreSQL. We use a multi-stage Docker build to keep the runtime image minimal and secure."

**Action:** Check the health endpoints.
```bash
curl http://localhost:8000/liveness
curl http://localhost:8000/readiness
```
**Talking Point:** "We have implemented Kubernetes-standard liveness and readiness probes. The readiness probe verifies that all our parsing and detection rules are loaded into the registry before accepting traffic."

---

## Step 2: Log Parsing

**Action:** Upload the sample attack log to the parsing endpoint.
```bash
curl -X POST -F "parser_name=regex" -F "file=@sample_data/attack_samples.log" http://localhost:8000/api/v1/parser/parse-file
```
**Talking Point:** "The parsing engine normalizes raw, unstructured logs (like Apache, Nginx, or custom regex) into structured `LogEvent` Pydantic models. Notice the file upload is protected by path traversal sanitization and a strict 10MB memory cap."

---

## Step 3: Threat Detection

**Action:** Pick one of the parsed events (e.g., the SQLi attack) and send it to the detection engine.
```bash
curl -X POST -H "Content-Type: application/json" -d '{"event": {"source_ip": "10.0.0.1", "endpoint": "/products?id=1'\'' UNION SELECT username, password FROM users--", "method": "GET", "timestamp": "2026-07-17T12:00:00Z", "raw_log": "..."}}' http://localhost:8000/api/v1/detection/detect
```
**Talking Point:** "The Detection Engine iterates through a registry of rules (SQLi, XSS, Path Traversal, etc.). Because we follow the Open/Closed Principle, adding a new detection rule simply requires creating a new class inheriting from `BaseRule`—no changes to the engine are needed. It outputs a standardized `DetectionAlert` mapped to MITRE ATT&CK."

---

## Step 4: Threat Intelligence Enrichment

**Action:** Send the `DetectionAlert` to the enrichment service.
```bash
# (Assuming you have a saved JSON alert payload from Step 3)
curl -X POST -H "Content-Type: application/json" -d @sample_data/sample_alert.json http://localhost:8000/api/v1/enrichment/enrich
```
**Talking Point:** "The Enrichment Service reaches out to AbuseIPDB and AlienVault OTX. To prevent rate-limiting and improve performance, results are stored in a thread-safe, LRU in-memory cache."

---

## Step 5: AI SOC Analyst

**Action:** Send the enriched alert to the AI service.
```bash
curl -X POST -H "Content-Type: application/json" -d @sample_data/sample_alert.json http://localhost:8000/api/v1/ai/analyze
```
**Talking Point:** "This is the AI SOC Analyst module. It uses structured JSON prompting to force the LLM (OpenAI/Gemini/Ollama) to act as a Tier-2 analyst. It calculates a false-positive probability and provides human-readable remediation steps."

---

## Step 6: Incident Reporting

**Action:** Generate a comprehensive report.
```bash
curl -X POST -H "Content-Type: application/json" -d '{"report_type": "incident", "alert": {...}, "ai_analysis": {...}, "enrichments": [...]}' http://localhost:8000/api/v1/reports/generate
```
**Action:** Export the PDF.
```bash
# Open in browser: http://localhost:8000/api/v1/reports/export/pdf
```
**Talking Point:** "The reporting engine uses a stateless 6-stage `TimelineEngine` to build a chronological sequence of the attack. We decouple the templates from the generators, allowing us to export to PDF (via reportlab), multi-sheet CSV, or nested JSON without changing the underlying business logic."

---

## Step 7: Architecture & Code Quality

**Action:** Show the codebase structure.
**Talking Point:** 
- "Notice the Clean Architecture: `routers` are extremely thin, delegating to `services`, which use `dependencies.py` for DI."
- "Show the CI/CD pipeline in `.github/workflows/ci.yml`. Every PR runs Black, Ruff, MyPy, Bandit (SAST), pip-audit, and requires >65% test coverage."
- "Show `app/middleware/core.py`. We have implemented strict security headers (CSP, HSTS) and structured JSON-lines logging."
