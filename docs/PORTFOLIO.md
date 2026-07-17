# Portfolio Overview: LogSentry SIEM

This document outlines the strategic value, engineering decisions, and technical depth of LogSentry for portfolio presentations and technical interviews.

## 1. Project Motivation

LogSentry was built to address a common gap in cybersecurity operations: the disconnect between raw log ingestion, threat detection, and actionable intelligence. As part of the larger **S.H.I.E.L.D.** platform vision, LogSentry serves as the analytical brain, automatically triaging noise so human analysts can focus on high-fidelity threats.

I wanted to demonstrate that I can build not just a "script that finds bad IPs," but a **production-ready, enterprise-grade backend** adhering to strict software engineering standards.

## 2. Engineering Challenges & Solutions

### Challenge 1: Extensibility in Detection
**Problem:** Hardcoding regex checks creates a fragile, unmaintainable detection engine.
**Solution:** Implemented a `RuleRegistry` using **SOLID principles** (specifically the Open/Closed Principle). New detection rules are added by subclassing `BaseRule` and implementing a `match()` method. The engine itself never needs modification when new attack vectors emerge.

### Challenge 2: API Rate Limits in Threat Intel
**Problem:** Calling AbuseIPDB/OTX for every log line would exhaust API quotas in seconds.
**Solution:** Built a thread-safe `InMemoryCache` with `threading.Lock` and an `OrderedDict` for LRU eviction. This drastically reduced outbound API calls while keeping memory bounded.

### Challenge 3: Reliable AI Parsing
**Problem:** LLMs often return conversational text instead of raw data.
**Solution:** Utilized strict system prompting and forced JSON mode (`response_format: {"type": "json_object"}`) via the OpenAI API. Built a provider-agnostic `BaseAIProvider` interface to allow seamless swapping between OpenAI, Gemini, and Ollama.

### Challenge 4: Security and Observability in Production
**Problem:** A security product must itself be secure and observable.
**Solution:** 
- Wrote custom ASGI middleware (`RequestSizeLimitMiddleware`) to drop oversized payloads before JSON parsing.
- Implemented a 7-header security suite (CSP, HSTS).
- Replaced standard logging with a `StructuredFormatter` that outputs JSON-Lines and auto-redacts sensitive keys (e.g., `api_key`).

## 3. Architecture Decisions

- **FastAPI / Python:** Chosen for high performance (ASGI) and rapid development, ideal for data-heavy ML/AI integrations.
- **Clean Architecture:** Separated into `routers`, `services`, `parsers`, and `detection`. This isolation allowed for 78 unit tests (77% coverage) because business logic is completely decoupled from HTTP concerns.
- **Dependency Injection:** Used FastAPI's `Depends()` heavily in `dependencies.py` to inject singleton services, making mocking during testing trivial.

## 4. Lessons Learned

- **Statelessness is crucial:** Designing the `TimelineEngine` (in the reporting module) to be completely stateless prevented race conditions and made unit testing drastically simpler.
- **Security requires depth:** Realized that just having CORS isn't enough; implementing path traversal protection in file uploads, size caps at the ASGI layer, and header sanitization were critical lessons in defense-in-depth.
- **Docker Multi-stage builds:** Reduced the final image size by ~40% by keeping build tools (GCC) in the builder stage and running the final image as a non-root user.

## 5. Future Roadmap (S.H.I.E.L.D. Vision)

- **Sprint 9:** Implement JWT authentication and Role-Based Access Control (RBAC).
- **v2.0:** Migrate from REST-only to an Event-Driven Architecture (Kafka/RabbitMQ) to broadcast alerts to the overarching S.H.I.E.L.D. event bus.
- **v2.1:** Implement Celery background workers for async PDF generation and AI analysis to prevent HTTP timeouts on massive log files.
