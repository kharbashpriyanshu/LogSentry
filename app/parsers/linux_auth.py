import re
from datetime import UTC, datetime

from app.parsers.base import BaseParser
from app.schemas.log_event import LogEvent

# Regex for common Linux auth.log / secure entries
_SSH_FAILED_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user\s+)?(?P<user>\S+)\s+"
    r"from (?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)

_SSH_ACCEPTED_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+sshd\[\d+\]:\s+"
    r"Accepted (?:password|publickey) for (?P<user>\S+)\s+"
    r"from (?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)

_SUDO_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+sudo:\s+"
    r"(?P<user>\S+)\s+:\s+TTY=\S+\s+;\s+PWD=\S+\s+;\s+USER=\S+\s+;\s+COMMAND=(?P<cmd>.*)$",
    re.IGNORECASE,
)


class LinuxAuthParser(BaseParser):
    """Parser for Linux /var/log/auth.log and /var/log/secure authentication logs."""

    @property
    def parser_name(self) -> str:
        return "linux_auth"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def supported_formats(self) -> list[str]:
        return ["Linux auth.log", "RHEL secure log", "SSH/Sudo auth"]

    @property
    def description(self) -> str:
        return "Parses Linux SSH authentication, sudo privilege escalation, and PAM events."

    def validate(self, log_line: str) -> bool:
        if not log_line:
            return False
        return any(k in log_line for k in ("sshd[", "sudo:", "useradd[", "su["))

    def parse_line(self, log_line: str) -> LogEvent | None:
        log_line = log_line.strip()
        if not log_line:
            return None

        now = datetime.now(UTC)

        # 1. SSH Failed Login
        m_failed = _SSH_FAILED_PATTERN.search(log_line)
        if m_failed:
            gd = m_failed.groupdict()
            return LogEvent(
                timestamp=now,
                source_ip=gd.get("ip"),
                hostname=gd.get("hostname"),
                user=gd.get("user"),
                method="AUTH",
                endpoint=f"/ssh/login?user={gd.get('user')}",
                action="SSH_FAILED_LOGIN",
                status_code=401,
                raw_log=log_line,
                parser_name=self.parser_name,
            )

        # 2. SSH Accepted Login
        m_accepted = _SSH_ACCEPTED_PATTERN.search(log_line)
        if m_accepted:
            gd = m_accepted.groupdict()
            return LogEvent(
                timestamp=now,
                source_ip=gd.get("ip"),
                hostname=gd.get("hostname"),
                user=gd.get("user"),
                method="AUTH",
                endpoint=f"/ssh/login?user={gd.get('user')}",
                action="SSH_ACCEPTED_LOGIN",
                status_code=200,
                raw_log=log_line,
                parser_name=self.parser_name,
            )

        # 3. Sudo Command
        m_sudo = _SUDO_PATTERN.search(log_line)
        if m_sudo:
            gd = m_sudo.groupdict()
            cmd = gd.get("cmd", "")
            return LogEvent(
                timestamp=now,
                hostname=gd.get("hostname"),
                user=gd.get("user"),
                method="EXEC",
                endpoint=f"/bin/sudo?cmd={cmd}",
                command_line=cmd,
                action="SUDO_EXEC",
                status_code=200,
                raw_log=log_line,
                parser_name=self.parser_name,
            )

        # Generic Linux Auth Entry
        return LogEvent(
            timestamp=now,
            method="AUTH",
            endpoint="/linux/auth",
            action="GENERIC_AUTH",
            status_code=200,
            raw_log=log_line,
            parser_name=self.parser_name,
        )
