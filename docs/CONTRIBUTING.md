# Contributing to LogSentry

Thank you for considering contributing to LogSentry SIEM.

---

## Development Setup

```bash
# Clone
git clone https://github.com/your-org/logsentry.git
cd logsentry

# Virtual environment
python -m venv .venv
source .venv/bin/activate

# Install all dev dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks (runs Black, Ruff, MyPy on every commit)
pre-commit install

# Copy environment config
cp .env.example .env
```

---

## Code Standards

| Tool | Purpose | Run |
|------|---------|-----|
| **Black** | Code formatting | `black .` |
| **Ruff** | Linting (E, F, B, I, S, N) | `ruff check .` |
| **MyPy** | Static type checking | `mypy app` |
| **Bandit** | Security scanning | `bandit -r app/` |

All checks run automatically via pre-commit and in CI.

---

## Architecture Principles

All contributions must follow:

1. **Clean Architecture** — keep layers separated (parsers → services → routers)
2. **SOLID** — one responsibility per class, depend on abstractions
3. **Dependency Injection** — wire dependencies in `app/api/dependencies.py`
4. **No secrets in code** — use environment variables only
5. **Type hints** — all public functions must have full type annotations
6. **Structured logging** — use `logger.info("msg", extra={...})` — never f-strings in log calls

---

## Testing Requirements

- All new features must have corresponding tests in `tests/`
- Coverage must not drop below **65%**
- Run tests with: `python -m pytest -v`

---

## Pull Request Process

1. Branch from `develop` (not `main`)
2. Name your branch: `feat/description`, `fix/description`, `chore/description`
3. Write/update tests
4. Ensure `pre-commit` passes locally
5. Open a PR against `develop`
6. All CI checks must pass before merge
7. At least one review approval required

---

## Directory Structure

```
app/
├── ai/          # AI SOC Analyst (providers, prompts)
├── api/         # FastAPI routers and dependencies
├── config/      # Settings (pydantic-settings)
├── core/        # Logging, shared utilities
├── detection/   # Detection rules and engine
├── enrichment/  # Threat intelligence providers and cache
├── exceptions/  # Global exception handlers
├── middleware/  # CoreMiddleware (security + observability)
├── models/      # Database ORM models
├── parsers/     # Log parsers (Apache, Nginx, Regex)
├── reports/     # Reporting engine (Sprint 7)
├── repositories/# Data access layer
├── schemas/     # Pydantic API schemas
└── services/    # Business logic orchestrators
```

---

## Commit Message Format

```
<type>(<scope>): <short description>

[optional body]

[optional footer: closes #issue]
```

Types: `feat`, `fix`, `chore`, `docs`, `test`, `refactor`, `perf`, `security`

Examples:
```
feat(detection): add SSRF detection rule
fix(enrichment): handle OTX timeout gracefully
security(middleware): add Content-Security-Policy header
```
