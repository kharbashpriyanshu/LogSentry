"""
Hardened ParsingService.

Changes from Sprint 7:
  - Added parse_uploaded() — separates "accept bytes from HTTP" from "parse a file path".
    The router now owns the temp-file lifecycle; the service only does parsing.
  - Removed internal temp-file management (SRP: service should parse, not manage files).
  - parse_file() is kept for backward compatibility but delegates to parse_uploaded().
  - Type hints completed throughout.
"""

import logging
import os
from typing import List, Tuple

from fastapi import UploadFile

from app.parsers.factory import ParserFactory
from app.schemas.log_event import LogEvent

logger = logging.getLogger(__name__)


class ParsingService:
    """Service layer for log parsing operations."""

    def parse_line(self, parser_name: str, log_line: str) -> LogEvent:
        """
        Parse a single log line using the named parser.

        Args:
            parser_name: Registered parser identifier (e.g. 'apache', 'nginx').
            log_line: Raw log string.

        Returns:
            Parsed LogEvent.

        Raises:
            ValueError: If the line does not match the parser's pattern.
            UnsupportedParserError: If parser_name is not registered.
        """
        parser = ParserFactory.get_parser(parser_name)
        event = parser.parse_line(log_line)
        if not event:
            raise ValueError(
                f"Log line does not match the '{parser_name}' parser format."
            )
        return event

    def parse_uploaded(
        self, parser_name: str, file_path: str
    ) -> Tuple[int, int, int, List[LogEvent]]:
        """
        Parse a log file at the given path.

        The caller is responsible for creating and deleting the file.
        This method is pure parsing — no I/O side effects.

        Args:
            parser_name: Registered parser identifier.
            file_path: Absolute path to the log file on disk.

        Returns:
            Tuple of (total_lines, successful, failed, events).
        """
        parser = ParserFactory.get_parser(parser_name)
        events = parser.parse_file(file_path)

        # Count non-empty lines to calculate failed parses
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                total_lines = sum(1 for line in fh if line.strip())
        except OSError as exc:
            logger.warning("Could not count lines in %s: %s", file_path, exc)
            total_lines = len(events)

        successful = len(events)
        failed = max(0, total_lines - successful)

        return total_lines, successful, failed, events

    # ------------------------------------------------------------------
    # Backward-compat shim (kept for existing tests)
    # ------------------------------------------------------------------

    async def parse_file(
        self, parser_name: str, file: UploadFile
    ) -> Tuple[int, int, int, List[LogEvent]]:
        """
        Legacy method: accepts an UploadFile, writes to a temp path, then parses.

        Prefer the router using parse_uploaded() directly for better separation.
        """
        import tempfile

        content = await file.read()
        suffix = os.path.splitext(file.filename or ".log")[1] or ".log"

        with tempfile.NamedTemporaryFile(
            delete=False, suffix=suffix, prefix="logsentry_compat_"
        ) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        try:
            return self.parse_uploaded(parser_name, tmp_path)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
