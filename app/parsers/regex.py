import re
from datetime import datetime, timezone
from typing import Optional
from app.parsers.base import BaseParser
from app.schemas.log_event import LogEvent
from app.parsers.exceptions import MalformedTimestampError
import logging

logger = logging.getLogger(__name__)

class RegexLogParser(BaseParser):
    """Base class for parsers that utilize Regular Expressions."""
    
    @property
    def pattern(self) -> re.Pattern:
        """The compiled regular expression pattern for the parser."""
        raise NotImplementedError
        
    def validate(self, log_line: str) -> bool:
        return bool(self.pattern.match(log_line))
        
    def _parse_timestamp(self, ts_str: str) -> datetime:
        """Parse timestamp and ensure UTC timezone awareness."""
        try:
            dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
            return dt.astimezone(timezone.utc)
        except ValueError:
            try:
                dt = datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S")
                return dt.replace(tzinfo=timezone.utc)
            except ValueError as e:
                raise MalformedTimestampError(f"Could not parse timestamp '{ts_str}': {e}")

    def parse_line(self, log_line: str) -> Optional[LogEvent]:
        try:
            match = self.pattern.match(log_line)
            if not match:
                logger.warning(f"Invalid format for {self.parser_name}. Line: {log_line[:50]}...")
                return None
                
            groups = match.groupdict()
            
            timestamp = None
            if "timestamp" in groups:
                try:
                    timestamp = self._parse_timestamp(groups["timestamp"])
                except MalformedTimestampError as e:
                    logger.warning(f"Timestamp error in {self.parser_name}: {e}. Line: {log_line[:50]}...")
                    
            size_str = groups.get("size", "")
            size = int(size_str) if size_str != "-" and size_str.isdigit() else None
            
            status_str = groups.get("status", "")
            status = int(status_str) if status_str.isdigit() else None
            
            return LogEvent(
                timestamp=timestamp,
                source_ip=groups.get("ip"),
                method=groups.get("method"),
                endpoint=groups.get("endpoint"),
                protocol=groups.get("protocol"),
                status_code=status,
                response_size=size,
                user_agent=groups.get("user_agent"),
                raw_log=log_line,
                parser_name=self.parser_name
            )
        except Exception as e:
            logger.error(f"Unexpected error parsing line: {e}. Line: {log_line[:50]}...", exc_info=True)
            return None
