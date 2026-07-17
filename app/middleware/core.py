import time
import uuid
import logging
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

logger = logging.getLogger(__name__)

class CoreMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        correlation_id = str(uuid.uuid4())
        request.state.correlation_id = correlation_id
        
        start_time = time.time()
        
        logger.info(f"[{correlation_id}] Request started: {request.method} {request.url.path}")
        
        try:
            response = await call_next(request)
        except Exception as e:
            # Ensure timing is calculated even if exception propagates up to handlers
            process_time = time.time() - start_time
            logger.info(f"[{correlation_id}] Request failed in {process_time:.4f} secs")
            raise e
            
        process_time = time.time() - start_time
        logger.info(f"[{correlation_id}] Request completed in {process_time:.4f} secs with status {response.status_code}")
            
        # Security headers
        response.headers["X-Correlation-ID"] = correlation_id
        response.headers["X-Process-Time"] = str(process_time)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            
        return response
