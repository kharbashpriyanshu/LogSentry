"""
Hardened exception handlers for the LogSentry API.

All handlers:
  - Return structured ErrorResponse JSON (consistent shape)
  - Include correlation_id from request state
  - Log at the appropriate level (warning for 4xx, error for 5xx)
  - NEVER leak internal stack traces or sensitive data in the response body

Reporting exceptions (InvalidReportTypeError, MissingReportDataError, etc.)
are also registered here to keep all HTTP→status-code mappings in one place.
"""

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.parsers.exceptions import ParserError, UnsupportedParserError
from app.ai.exceptions import (
    AIError,
    AIProviderUnavailableError,
    AIRateLimitError,
    AITimeoutError,
)
from app.reports.exceptions import (
    CSVExportError,
    InvalidReportTypeError,
    JSONSerializationError,
    MissingReportDataError,
    PDFGenerationError,
    ReportingError,
)
from app.schemas.api import ErrorResponse

logger = logging.getLogger(__name__)


def _cid(request: Request) -> str:
    return getattr(request.state, "correlation_id", "unknown")


def _error(error: str, details: str, correlation_id: str) -> dict:
    return ErrorResponse(
        error=error,
        details=details,
        correlation_id=correlation_id,
    ).model_dump()


def add_exception_handlers(app: FastAPI) -> None:  # noqa: C901

    # ------------------------------------------------------------------
    # 422 – Validation
    # ------------------------------------------------------------------

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):
        cid = _cid(request)
        logger.warning(
            "Request validation failed",
            extra={
                "correlation_id": cid,
                "path": str(request.url),
                "errors": exc.errors(),
            },
        )
        return JSONResponse(
            status_code=422,
            content=_error("Validation Error", str(exc.errors()), cid),
        )

    # ------------------------------------------------------------------
    # Parser errors → 400
    # ------------------------------------------------------------------

    @app.exception_handler(UnsupportedParserError)
    async def unsupported_parser_handler(request: Request, exc: UnsupportedParserError):
        return JSONResponse(
            status_code=400,
            content=_error("Unsupported Parser", str(exc), _cid(request)),
        )

    @app.exception_handler(ParserError)
    async def parser_error_handler(request: Request, exc: ParserError):
        return JSONResponse(
            status_code=400,
            content=_error("Parsing Error", str(exc), _cid(request)),
        )

    # ------------------------------------------------------------------
    # Reporting errors
    # ------------------------------------------------------------------

    @app.exception_handler(InvalidReportTypeError)
    async def invalid_report_type_handler(request: Request, exc: InvalidReportTypeError):
        return JSONResponse(
            status_code=400,
            content=_error("Invalid Report Type", str(exc), _cid(request)),
        )

    @app.exception_handler(MissingReportDataError)
    async def missing_report_data_handler(request: Request, exc: MissingReportDataError):
        return JSONResponse(
            status_code=422,
            content=_error("Missing Report Data", str(exc), _cid(request)),
        )

    @app.exception_handler(PDFGenerationError)
    async def pdf_generation_handler(request: Request, exc: PDFGenerationError):
        cid = _cid(request)
        logger.error("PDF generation failed", extra={"correlation_id": cid, "reason": exc.reason})
        return JSONResponse(
            status_code=500,
            content=_error("PDF Generation Failed", str(exc), cid),
        )

    @app.exception_handler(CSVExportError)
    async def csv_export_handler(request: Request, exc: CSVExportError):
        cid = _cid(request)
        logger.error("CSV export failed", extra={"correlation_id": cid, "reason": exc.reason})
        return JSONResponse(
            status_code=500,
            content=_error("CSV Export Failed", str(exc), cid),
        )

    @app.exception_handler(JSONSerializationError)
    async def json_serialization_handler(request: Request, exc: JSONSerializationError):
        cid = _cid(request)
        logger.error("JSON serialization failed", extra={"correlation_id": cid, "reason": exc.reason})
        return JSONResponse(
            status_code=500,
            content=_error("JSON Serialization Failed", str(exc), cid),
        )

    @app.exception_handler(ReportingError)
    async def generic_reporting_handler(request: Request, exc: ReportingError):
        cid = _cid(request)
        logger.error("Reporting error", extra={"correlation_id": cid})
        return JSONResponse(
            status_code=500,
            content=_error("Reporting Error", str(exc), cid),
        )

    # ------------------------------------------------------------------
    # AI errors
    # ------------------------------------------------------------------

    @app.exception_handler(AIProviderUnavailableError)
    async def ai_unavailable_handler(request: Request, exc: AIProviderUnavailableError):
        return JSONResponse(
            status_code=503,
            content=_error("AI Provider Unavailable", str(exc), _cid(request)),
        )

    @app.exception_handler(AITimeoutError)
    async def ai_timeout_handler(request: Request, exc: AITimeoutError):
        return JSONResponse(
            status_code=504,
            content=_error("AI Provider Timeout", str(exc), _cid(request)),
        )

    @app.exception_handler(AIRateLimitError)
    async def ai_ratelimit_handler(request: Request, exc: AIRateLimitError):
        return JSONResponse(
            status_code=429,
            content=_error("AI Rate Limit Exceeded", str(exc), _cid(request)),
        )

    @app.exception_handler(AIError)
    async def generic_ai_handler(request: Request, exc: AIError):
        cid = _cid(request)
        logger.error("AI processing error", extra={"correlation_id": cid})
        return JSONResponse(
            status_code=502,
            content=_error("AI Processing Error", str(exc), cid),
        )

    # ------------------------------------------------------------------
    # Generic HTTP exceptions
    # ------------------------------------------------------------------

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content=_error("HTTP Error", str(exc.detail), _cid(request)),
        )

    # ------------------------------------------------------------------
    # Catch-all — 500 with sanitised message
    # ------------------------------------------------------------------

    @app.exception_handler(Exception)
    async def unexpected_handler(request: Request, exc: Exception):
        cid = _cid(request)
        logger.error(
            "Unhandled exception",
            extra={
                "correlation_id": cid,
                "method": request.method,
                "path": str(request.url),
            },
            exc_info=True,
        )
        return JSONResponse(
            status_code=500,
            content=_error(
                "Internal Server Error",
                "An unexpected error occurred. Please contact an administrator.",
                cid,
            ),
        )
