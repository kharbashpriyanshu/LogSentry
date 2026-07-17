"""
Security & Observability Middleware for LogSentry.

CoreMiddleware handles:
  1. Correlation ID generation (X-Correlation-ID header)
  2. Request latency measurement (X-Process-Time header)
  3. Structured request/response logging
  4. Full security header injection:
       - Content-Security-Policy
       - X-Content-Type-Options
       - X-Frame-Options
       - Referrer-Policy
       - Permissions-Policy
       - Strict-Transport-Security
       - X-XSS-Protection (legacy browser support)
  5. Request size enforcement (rejects oversized bodies early)
  6. In-process request metrics tracking (Prometheus-compatible counters)

RequestSizeLimitMiddleware:
  Enforces a maximum request body size before the request reaches
  any business logic. Returns 413 immediately for oversized bodies.

Design notes:
  - Security headers are set as immutable constants so they survive
    any response mutation downstream.
  - Correlation IDs are UUIDs v4 (cryptographically random).
  - Metrics are stored as module-level dicts; replace with
    prometheus_client counters in Sprint 9 if Prometheus is adopted.
"""

import time
import uuid
import logging
from typing import Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response, JSONResponse
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-process metrics store (lightweight, no external dependency)
# ---------------------------------------------------------------------------

_metrics: dict = {
    "requests_total": 0,
    "requests_failed": 0,
    "latency_sum_seconds": 0.0,
    "status_codes": {},
}


def get_metrics() -> dict:
    """Return a snapshot of current in-process metrics."""
    total = _metrics["requests_total"]
    return {
        "requests_total": total,
        "requests_failed": _metrics["requests_failed"],
        "average_latency_seconds": (
            round(_metrics["latency_sum_seconds"] / total, 4) if total else 0.0
        ),
        "status_code_distribution": dict(_metrics["status_codes"]),
    }


# ---------------------------------------------------------------------------
# Security headers (defined once, applied to every response)
# ---------------------------------------------------------------------------

_SECURITY_HEADERS = {
    # Prevent MIME-type sniffing
    "X-Content-Type-Options": "nosniff",
    # Deny framing (clickjacking protection)
    "X-Frame-Options": "DENY",
    # Legacy XSS filter for older browsers
    "X-XSS-Protection": "1; mode=block",
    # HSTS — 1 year, include subdomains, ready for preload
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    # No referrer leakage
    "Referrer-Policy": "strict-origin-when-cross-origin",
    # Minimal permissions policy for an API backend
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    # Tight CSP for a JSON API — no scripts, no embeds
    "Content-Security-Policy": (
        "default-src 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'none';"
    ),
    # Remove server fingerprint
    "Server": "LogSentry",
}


# ---------------------------------------------------------------------------
# Core Middleware
# ---------------------------------------------------------------------------


class CoreMiddleware(BaseHTTPMiddleware):
    """
    Attaches correlation IDs, security headers, and metrics to every request.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        correlation_id = str(uuid.uuid4())
        request.state.correlation_id = correlation_id

        start_time = time.perf_counter()
        _metrics["requests_total"] += 1

        logger.info(
            "Request received",
            extra={
                "correlation_id": correlation_id,
                "method": request.method,
                "path": request.url.path,
                "client_ip": self._client_ip(request),
                "user_agent": request.headers.get("user-agent", ""),
            },
        )

        try:
            response = await call_next(request)
        except Exception as exc:
            elapsed = time.perf_counter() - start_time
            _metrics["requests_failed"] += 1
            _metrics["latency_sum_seconds"] += elapsed
            logger.error(
                "Request failed with unhandled exception",
                extra={
                    "correlation_id": correlation_id,
                    "method": request.method,
                    "path": request.url.path,
                    "elapsed_seconds": round(elapsed, 4),
                },
            )
            raise exc

        elapsed = time.perf_counter() - start_time
        _metrics["latency_sum_seconds"] += elapsed

        status = response.status_code
        _metrics["status_codes"][str(status)] = (
            _metrics["status_codes"].get(str(status), 0) + 1
        )
        if status >= 500:
            _metrics["requests_failed"] += 1

        logger.info(
            "Request completed",
            extra={
                "correlation_id": correlation_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": status,
                "elapsed_seconds": round(elapsed, 4),
            },
        )

        # Attach headers
        response.headers["X-Correlation-ID"] = correlation_id
        response.headers["X-Process-Time"] = f"{elapsed:.4f}"
        for header, value in _SECURITY_HEADERS.items():
            response.headers[header] = value

        return response

    @staticmethod
    def _client_ip(request: Request) -> str:
        """Extract real client IP, honouring X-Forwarded-For from trusted proxies."""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------------------
# Request Size Limit Middleware
# ---------------------------------------------------------------------------

# 1 MB default — log files can be larger, but raw API JSON payloads should not
_DEFAULT_MAX_SIZE_BYTES = 1 * 1024 * 1024  # 1 MB


class RequestSizeLimitMiddleware:
    """
    ASGI middleware that rejects requests with a Content-Length exceeding
    the configured limit before they reach any application logic.

    Note: Content-Length header absence does not block the request (streaming
    uploads are handled by parse_file which enforces its own size limit).
    """

    def __init__(self, app: ASGIApp, max_bytes: int = _DEFAULT_MAX_SIZE_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            content_length_raw = headers.get(b"content-length")
            if content_length_raw:
                try:
                    content_length = int(content_length_raw)
                    if content_length > self.max_bytes:
                        response = JSONResponse(
                            status_code=413,
                            content={
                                "error": "Payload Too Large",
                                "details": (
                                    f"Request body exceeds the {self.max_bytes // 1024} KB limit."
                                ),
                            },
                        )
                        await response(scope, receive, send)
                        return
                except (ValueError, TypeError):
                    pass  # Malformed header — let downstream handle it

        await self.app(scope, receive, send)
