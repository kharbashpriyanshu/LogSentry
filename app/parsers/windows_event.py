import json
import logging
from datetime import UTC, datetime

from app.parsers.base import BaseParser
from app.schemas.log_event import LogEvent

logger = logging.getLogger(__name__)


class WindowsEventParser(BaseParser):
    """Parser for Windows Security Event Logs (JSON and Structured Sysmon/EVTX)."""

    @property
    def parser_name(self) -> str:
        return "windows_event"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def supported_formats(self) -> list[str]:
        return ["Windows EVTX JSON", "Sysmon JSON", "Security Event Log"]

    @property
    def description(self) -> str:
        return "Parses Windows Security Events: 4624 (Logon), 4625 (Failed Logon), 4688 (Process Create), 4104 (PowerShell)."

    def validate(self, log_line: str) -> bool:
        if not log_line:
            return False
        # Fast check for JSON containing EventID / EventData or typical Windows event markers
        return any(
            k in log_line
            for k in ("EventID", "event_id", "4624", "4625", "4688", "4104")
        )

    def parse_line(self, log_line: str) -> LogEvent | None:
        log_line = log_line.strip()
        if not log_line:
            return None

        now = datetime.now(UTC)

        # Attempt JSON parsing first (standard for modern SIEM collectors like Winlogbeat / nxlog)
        if log_line.startswith("{") and log_line.endswith("}"):
            try:
                data = json.loads(log_line)
                event_id = str(data.get("EventID") or data.get("event_id") or "")
                event_data = data.get("EventData") or data.get("event_data") or {}

                # Extract key attributes
                user = (
                    event_data.get("TargetUserName")
                    or event_data.get("SubjectUserName")
                    or data.get("user")
                )
                source_ip = (
                    event_data.get("IpAddress")
                    or event_data.get("SourceIp")
                    or data.get("source_ip")
                )
                if source_ip == "-" or source_ip == "::1":
                    source_ip = "127.0.0.1"

                computer = (
                    data.get("Computer")
                    or data.get("hostname")
                    or event_data.get("WorkstationName")
                )
                command_line = event_data.get("CommandLine") or event_data.get(
                    "ScriptBlockText"
                )
                process_name = event_data.get("NewProcessName") or event_data.get(
                    "ProcessName"
                )

                # Map event codes
                status_code = 401 if event_id == "4625" else 200
                action_map = {
                    "4624": "LOGON_SUCCESS",
                    "4625": "LOGON_FAILURE",
                    "4688": "PROCESS_CREATION",
                    "4104": "POWERSHELL_SCRIPT_BLOCK",
                }
                action = action_map.get(event_id, f"EVENT_{event_id}")

                # Build simulated endpoint for rule matching
                endpoint = f"/windows/event/{event_id}"
                if command_line:
                    endpoint = f"/windows/exec?cmd={command_line}"
                elif user:
                    endpoint = f"/windows/auth?user={user}"

                return LogEvent(
                    timestamp=now,
                    source_ip=source_ip,
                    hostname=computer,
                    user=user,
                    event_id=event_id,
                    action=action,
                    method="EVENT",
                    endpoint=endpoint,
                    command_line=command_line,
                    process_name=process_name,
                    status_code=status_code,
                    raw_log=log_line,
                    parser_name=self.parser_name,
                )
            except Exception as e:
                logger.debug(f"JSON Windows Event parsing fallback: {e}")

        # Fallback text parsing for plaintext Event ID logs
        event_id = "UNKNOWN"
        for eid in ("4624", "4625", "4688", "4104"):
            if eid in log_line:
                event_id = eid
                break

        return LogEvent(
            timestamp=now,
            event_id=event_id,
            action=f"EVENT_{event_id}",
            method="EVENT",
            endpoint=f"/windows/event/{event_id}",
            status_code=401 if event_id == "4625" else 200,
            raw_log=log_line,
            parser_name=self.parser_name,
        )
