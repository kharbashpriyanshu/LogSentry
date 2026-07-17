from fastapi import Request, FastAPI
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
import logging
from app.parsers.exceptions import ParserError, UnsupportedParserError
from app.schemas.api import ErrorResponse

logger = logging.getLogger(__name__)

def add_exception_handlers(app: FastAPI):
    
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        correlation_id = getattr(request.state, "correlation_id", "unknown")
        logger.warning(f"[{correlation_id}] Validation error on {request.url}: {exc.errors()}")
        return JSONResponse(
            status_code=422,
            content=ErrorResponse(
                error="Validation Error",
                details=str(exc.errors()),
                correlation_id=correlation_id
            ).model_dump()
        )

    @app.exception_handler(UnsupportedParserError)
    async def unsupported_parser_handler(request: Request, exc: UnsupportedParserError):
        correlation_id = getattr(request.state, "correlation_id", "unknown")
        return JSONResponse(
            status_code=400,
            content=ErrorResponse(
                error="Unsupported Parser",
                details=str(exc),
                correlation_id=correlation_id
            ).model_dump()
        )

    @app.exception_handler(ParserError)
    async def parser_error_handler(request: Request, exc: ParserError):
        correlation_id = getattr(request.state, "correlation_id", "unknown")
        return JSONResponse(
            status_code=400,
            content=ErrorResponse(
                error="Parsing Error",
                details=str(exc),
                correlation_id=correlation_id
            ).model_dump()
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        correlation_id = getattr(request.state, "correlation_id", "unknown")
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(
                error="HTTP Error",
                details=exc.detail,
                correlation_id=correlation_id
            ).model_dump()
        )

    @app.exception_handler(Exception)
    async def unexpected_exception_handler(request: Request, exc: Exception):
        correlation_id = getattr(request.state, "correlation_id", "unknown")
        logger.error(f"[{correlation_id}] Unexpected error handling {request.method} {request.url}: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error="Internal Server Error",
                details="An unexpected error occurred. Please contact an administrator.",
                correlation_id=correlation_id
            ).model_dump()
        )
