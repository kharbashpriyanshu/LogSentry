# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Active  |

## Reporting a Vulnerability

**Do NOT open a public GitHub Issue for security vulnerabilities.**

Please report security vulnerabilities via one of the following channels:

- **Email**: security@logsentry.local
- **Subject line**: `[SECURITY] LogSentry — <brief description>`

You will receive an acknowledgement within **24 hours** and a patch within **14 days** for critical issues.

Please include in your report:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested remediation (optional)

## Security Architecture

### Authentication & Authorization
- LogSentry Sprint 8 does not implement authentication (planned for Sprint 9).
- All endpoints are currently open. **Do not expose to the public internet without a reverse proxy enforcing auth.**

### Security Headers
Every HTTP response includes:
- `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; form-action 'none'`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: geolocation=(), microphone=(), camera=()`

### Input Validation
- All API inputs are validated via Pydantic v2 models with strict types.
- File uploads are validated for: filename (path traversal protection), content-type (allowlist), and size (configurable cap, default 10 MB).
- Request body size is capped at 1 MB (configurable) before any parsing occurs.

### Secret Handling
- API keys are loaded exclusively from environment variables / `.env` files.
- Keys are **never logged**. The `StructuredFormatter` scrubs any dict key matching: `api_key`, `password`, `token`, `secret`, `authorization`, `key`.
- `.env` is listed in `.gitignore`.

### CORS
- Strict allowlist (no wildcards). Configure `CORS_ALLOWED_ORIGINS` in `.env`.
- Restricted methods: `GET`, `POST`, `OPTIONS` only.

### Dependencies
- All dependencies are audited with `pip-audit` in the CI pipeline.
- Security scanning runs on every pull request via `bandit` (high-severity blocks the build).

## Known Limitations (Sprint 9 Backlog)

- No authentication or rate limiting implemented yet.
- No TLS termination inside the application (offload to nginx/traefik in production).
- In-memory report cache (`_last_report`) is not persisted across restarts.
- Database connection pool has no connection-level authentication enforcement.
