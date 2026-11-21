import logging
import re
from datetime import UTC, datetime, timedelta, timezone

from app.parsers.base import BaseParser
from app.parsers.exceptions import MalformedTimestampError
from app.schemas.log_event import LogEvent

logger = logging.getLogger(__name__)

_MONTH_MAP = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


class RegexLogParser(BaseParser):
    """Base class for parsers that utilize Regular Expressions."""

    @property
    def pattern(self) -> re.Pattern:
        """The compiled regular expression pattern for the parser."""
        raise NotImplementedError

    def validate(self, log_line: str) -> bool:
        return bool(self.pattern.match(log_line))

    def _parse_timestamp(self, ts_str: str) -> datetime:
        """Parse timestamp and ensure UTC timezone awareness using fast slice parser with fallback."""
        try:
            # Fast-path for standard Apache/Nginx format: '10/Oct/2000:13:55:36 -0700'
            if (
                len(ts_str) >= 20
                and ts_str[2] == "/"
                and ts_str[6] == "/"
                and ts_str[11] == ":"
            ):
                day = int(ts_str[0:2])
                mon = _MONTH_MAP.get(ts_str[3:6])
                if mon is not None:
                    year = int(ts_str[7:11])
                    hour = int(ts_str[12:14])
                    minute = int(ts_str[15:17])
                    second = int(ts_str[18:20])

                    if len(ts_str) >= 26 and (ts_str[21] == "+" or ts_str[21] == "-"):
                        sign = -1 if ts_str[21] == "-" else 1
                        tz_h = int(ts_str[22:24])
                        tz_m = int(ts_str[24:26])
                        tz = timezone(sign * timedelta(hours=tz_h, minutes=tz_m))
                        return datetime(
                            year, mon, day, hour, minute, second, tzinfo=tz
                        ).astimezone(UTC)
                    return datetime(year, mon, day, hour, minute, second, tzinfo=UTC)
        except Exception:
            pass

        # Robust standard fallback
        try:
            dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
            return dt.astimezone(UTC)
        except ValueError:
            try:
                dt = datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S")
                return dt.replace(tzinfo=UTC)
            except ValueError as e:
                raise MalformedTimestampError(
                    f"Could not parse timestamp '{ts_str}': {e}"
                )

    def parse_line(self, log_line: str) -> LogEvent | None:
        try:
            match = self.pattern.match(log_line)
            if not match:
                logger.warning(
                    f"Invalid format for {self.parser_name}. Line: {log_line[:50]}..."
                )
                return None

            groups = match.groupdict()

            timestamp = None
            if "timestamp" in groups:
                try:
                    timestamp = self._parse_timestamp(groups["timestamp"])
                except MalformedTimestampError as e:
                    logger.warning(
                        f"Timestamp error in {self.parser_name}: {e}. Line: {log_line[:50]}..."
                    )

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
                parser_name=self.parser_name,
            )
        except Exception as e:
            logger.error(
                f"Unexpected error parsing line: {e}. Line: {log_line[:50]}...",
                exc_info=True,
            )
            return None
