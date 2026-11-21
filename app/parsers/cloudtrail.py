import json
import logging
from datetime import UTC, datetime

from app.parsers.base import BaseParser
from app.schemas.log_event import LogEvent

logger = logging.getLogger(__name__)


class AWSCloudTrailParser(BaseParser):
    """Parser for AWS CloudTrail API audit logs and VPC flow events."""

    @property
    def parser_name(self) -> str:
        return "cloudtrail"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def supported_formats(self) -> list[str]:
        return ["AWS CloudTrail JSON", "AWS API Audit Event"]

    @property
    def description(self) -> str:
        return "Parses AWS CloudTrail JSON records for IAM, STS, and API security analysis."

    def validate(self, log_line: str) -> bool:
        if not log_line:
            return False
        return any(
            k in log_line
            for k in ("eventSource", "awsRegion", "userIdentity", "CloudTrail")
        )

    def parse_line(self, log_line: str) -> LogEvent | None:
        log_line = log_line.strip()
        if not log_line:
            return None

        now = datetime.now(UTC)

        try:
            data = json.loads(log_line)
            event_name = data.get("eventName", "UnknownAPI")
            event_source = data.get("eventSource", "aws")
            source_ip = data.get("sourceIPAddress")
            user_identity = data.get("userIdentity", {})
            user = (
                user_identity.get("userName")
                or user_identity.get("principalId")
                or user_identity.get("arn")
            )
            error_code = data.get("errorCode")
            status_code = 403 if error_code else 200

            endpoint = f"/aws/{event_source}/{event_name}"
            if error_code:
                endpoint += f"?error={error_code}"

            return LogEvent(
                timestamp=now,
                source_ip=source_ip,
                hostname=data.get("awsRegion", "global"),
                user=user,
                action=f"AWS_{event_name.upper()}",
                method="API",
                endpoint=endpoint,
                status_code=status_code,
                raw_log=log_line,
                parser_name=self.parser_name,
            )
        except Exception as e:
            logger.debug(f"CloudTrail parse failed: {e}")
            return None
