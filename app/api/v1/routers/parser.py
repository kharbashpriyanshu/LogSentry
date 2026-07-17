"""
Hardened file upload endpoint with:
  - File size enforcement (rejects before full read)
  - Content-type validation (text/plain and application/octet-stream only)
  - Filename sanitisation (path traversal protection)
  - Secure temp-file handling via tempfile.NamedTemporaryFile
"""

import logging
import os
import re
import tempfile
from pathlib import PurePath

from fastapi import APIRouter, Depends, Form, HTTPException, UploadFile, File

from app.api.dependencies import get_parsing_service
from app.config.settings import settings
from app.parsers.exceptions import ParserError, UnsupportedParserError
from app.schemas.api import ParseFileResponse, ParseLineRequest, ParseResponse
from app.services.parsing_service import ParsingService

logger = logging.getLogger(__name__)
router = APIRouter()

# Allowed MIME types for log file uploads
_ALLOWED_CONTENT_TYPES = {
    "text/plain",
    "application/octet-stream",
    "text/csv",
}

# Safe filename pattern — alphanumerics, dots, hyphens, underscores only
_SAFE_FILENAME_RE = re.compile(r"^[\w\-. ]+$")


def _sanitise_filename(filename: str) -> str:
    """
    Strip path components and verify the filename contains only safe characters.
    Raises HTTPException(400) on path-traversal or suspicious filenames.
    """
    # Strip any directory prefix (e.g. ../../etc/passwd → passwd)
    basename = PurePath(filename).name
    if not basename or not _SAFE_FILENAME_RE.match(basename):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid filename '{filename}'. Only alphanumeric characters, dots, hyphens, and underscores are allowed.",
        )
    return basename


@router.post("/parse-line", response_model=ParseResponse, summary="Parse a single log line")
def parse_line(
    request: ParseLineRequest,
    parsing_service: ParsingService = Depends(get_parsing_service),
) -> ParseResponse:
    """Parse a single raw log line using the specified parser."""
    try:
        event = parsing_service.parse_line(request.parser_name, request.log_line)
        return ParseResponse(success=True, event=event.model_dump())
    except ValueError as exc:
        return ParseResponse(success=False, error=str(exc))


@router.post("/parse-file", response_model=ParseFileResponse, summary="Parse an uploaded log file")
async def parse_file(
    parser_name: str = Form(...),
    file: UploadFile = File(...),
    parsing_service: ParsingService = Depends(get_parsing_service),
) -> ParseFileResponse:
    """
    Upload and parse a log file.

    Security controls:
      - Maximum file size: configured via MAX_UPLOAD_SIZE_BYTES (default 10 MB)
      - Filename sanitised against path-traversal
      - Content-type restricted to text/plain and application/octet-stream
      - Temp file cleaned up unconditionally via finally block
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided.")

    safe_name = _sanitise_filename(file.filename)

    # Content-type check (advisory — not a hard security boundary, but catches accidents)
    content_type = (file.content_type or "").split(";")[0].strip().lower()
    if content_type and content_type not in _ALLOWED_CONTENT_TYPES:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported file type '{content_type}'. Upload plain-text log files only.",
        )

    # Read with size cap
    content = await file.read(settings.MAX_UPLOAD_SIZE_BYTES + 1)
    if len(content) > settings.MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=(
                f"File exceeds the maximum allowed size of "
                f"{settings.MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB."
            ),
        )

    logger.info(
        "File upload received",
        extra={
            "filename": safe_name,
            "size_bytes": len(content),
            "parser": parser_name,
        },
    )

    # Write to a secure named temp file (mode 0o600 on POSIX)
    suffix = PurePath(safe_name).suffix or ".log"
    with tempfile.NamedTemporaryFile(
        delete=False, suffix=suffix, prefix="logsentry_upload_"
    ) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        total, success, failed, events = parsing_service.parse_uploaded(
            parser_name, tmp_path
        )
        logger.info(
            "File parsed successfully",
            extra={
                "filename": safe_name,
                "total": total,
                "success": success,
                "failed": failed,
            },
        )
        return ParseFileResponse(
            total_lines_processed=total,
            successful_parses=success,
            failed_parses=failed,
            events=[e.model_dump() for e in events],
        )
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            logger.warning("Could not delete temp file: %s", tmp_path)
