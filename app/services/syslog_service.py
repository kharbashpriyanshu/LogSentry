import asyncio
import logging
import re
from datetime import UTC, datetime
from typing import Any

from app.detection.engine import DetectionEngine
from app.parsers.factory import ParserFactory
from app.schemas.log_event import LogEvent
from app.services.soar_service import SOARService
from app.services.websocket import ConnectionManager

logger = logging.getLogger(__name__)

# RFC 5424 format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
_RFC5424_PATTERN = re.compile(
    r"^<(?P<pri>\d{1,3})>1\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<app_name>\S+)\s+"
    r"(?P<proc_id>\S+)\s+"
    r"(?P<msg_id>\S+)\s+"
    r"(?:\[(?P<sd>[^\]]*)\])?\s*"
    r"(?P<msg>.*)$",
    re.DOTALL,
)

# RFC 3164 format: <PRI>Mmm dd hh:mm:ss HOSTNAME TAG: MSG
_RFC3164_PATTERN = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>[a-zA-Z0-9_.-]+)\s+"
    r"(?P<tag>[a-zA-Z0-9_.-]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<msg>.*)$",
    re.DOTALL,
)


def parse_syslog_framing(raw_line: str) -> dict[str, Any]:
    """Parse raw RFC 5424 or RFC 3164 framing into structured metadata and payload."""
    raw_line = raw_line.strip()

    # Try RFC 5424
    match_5424 = _RFC5424_PATTERN.match(raw_line)
    if match_5424:
        gd = match_5424.groupdict()
        pri = int(gd["pri"])
        return {
            "format": "RFC5424",
            "pri": pri,
            "facility": pri >> 3,
            "severity": pri & 7,
            "timestamp": gd["timestamp"],
            "hostname": None if gd["hostname"] == "-" else gd["hostname"],
            "app_name": None if gd["app_name"] == "-" else gd["app_name"],
            "proc_id": None if gd["proc_id"] == "-" else gd["proc_id"],
            "msg_id": None if gd["msg_id"] == "-" else gd["msg_id"],
            "msg": gd["msg"].strip(),
        }

    # Try RFC 3164
    match_3164 = _RFC3164_PATTERN.match(raw_line)
    if match_3164:
        gd = match_3164.groupdict()
        pri = int(gd["pri"])
        return {
            "format": "RFC3164",
            "pri": pri,
            "facility": pri >> 3,
            "severity": pri & 7,
            "timestamp": gd["timestamp"],
            "hostname": gd["hostname"],
            "app_name": gd["tag"],
            "proc_id": gd.get("pid"),
            "msg": gd["msg"].strip(),
        }

    # Fallback: Strip leading <PRI> tag if present
    pri_fallback = re.match(r"^<(?P<pri>\d{1,3})>(?:\d\s+)?", raw_line)
    if pri_fallback:
        pri = int(pri_fallback.group("pri"))
        clean = raw_line[pri_fallback.end() :].strip()
        return {
            "format": "LEGACY",
            "pri": pri,
            "facility": pri >> 3,
            "severity": pri & 7,
            "msg": clean,
        }

    return {"format": "RAW", "msg": raw_line}


class SyslogProtocol(asyncio.DatagramProtocol):
    """Async UDP Protocol for receiving RFC 3164 / 5424 syslog streams."""

    def __init__(self, service: "SyslogService"):
        self.service = service

    def datagram_received(self, data: bytes, addr):
        raw_msg = data.decode("utf-8", errors="ignore").strip()
        if raw_msg:
            self.service.process_raw_message(raw_msg, addr[0] if addr else None)


class SyslogService:
    """Manager for the live background Syslog ingestion listener (UDP + TCP)."""

    def __init__(self, host: str = "0.0.0.0", port: int = 1514):
        self.host = host
        self.port = port
        self.is_running = False
        self.udp_transport: asyncio.DatagramTransport | None = None
        self.tcp_server: asyncio.Server | None = None
        self.engine = DetectionEngine()
        self.total_received = 0
        self.total_parsed = 0
        self.total_alerts = 0
        self.total_errors = 0
        self.started_at: str | None = None
        self.last_received_at: str | None = None

    def process_raw_message(
        self, raw_msg: str, client_ip: str | None = None
    ) -> LogEvent | None:
        """Process incoming raw syslog message from UDP or TCP stream."""
        self.total_received += 1
        self.last_received_at = datetime.now(UTC).isoformat()

        try:
            parsed_frame = parse_syslog_framing(raw_msg)
            content_msg = parsed_frame.get("msg") or raw_msg

            # Try to identify an IP address in the payload if available
            ip_match = re.search(
                r"\b(?:\d{1,3}\.){3}\d{1,3}\s+[-a-zA-Z0-9_]+\s+", content_msg
            )
            clean_log = (
                content_msg[ip_match.start() :].strip() if ip_match else content_msg
            )

            # Intelligent parser selection based on framing or content guessing
            parser = None
            app_name = str(parsed_frame.get("app_name") or "").lower()

            if any(k in app_name for k in ("ssh", "sudo", "su", "auth", "login")):
                try:
                    parser = ParserFactory.get_parser("linux_auth")
                except Exception:
                    pass

            if not parser:
                try:
                    parser = ParserFactory.guess_parser(clean_log)
                except Exception:
                    parser = None

            event = parser.parse_line(clean_log) if parser else None
            if not event:
                event = LogEvent(
                    timestamp=datetime.now(UTC),
                    source_ip=client_ip,
                    raw_log=raw_msg,
                    parser_name=parser.parser_name if parser else "syslog",
                    hostname=parsed_frame.get("hostname"),
                )

            if not event.source_ip and client_ip:
                event.source_ip = client_ip
            if not event.hostname and parsed_frame.get("hostname"):
                event.hostname = parsed_frame.get("hostname")

            self.total_parsed += 1

            # Run detection engine
            alerts = self.engine.process_event(event)
            if alerts:
                self.total_alerts += len(alerts)
                for alert in alerts:
                    SOARService.evaluate_auto_containment(alert)
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(
                            ConnectionManager.broadcast_event(
                                "new_alert", alert.model_dump(mode="json")
                            )
                        )
                    except Exception:
                        pass

            return event
        except Exception as e:
            self.total_errors += 1
            logger.error(f"Error processing syslog message from {client_ip}: {e}")
            return None

    async def _handle_tcp_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        """Handle streaming TCP syslog connections."""
        peer = writer.get_extra_info("peername")
        client_ip = peer[0] if peer else None
        try:
            while not reader.at_eof():
                line = await reader.readline()
                if not line:
                    break
                decoded = line.decode("utf-8", errors="ignore").strip()
                if decoded:
                    self.process_raw_message(decoded, client_ip)
        except Exception as e:
            logger.debug(f"TCP syslog client connection ended: {e}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self) -> bool:
        if self.is_running:
            return True

        try:
            loop = asyncio.get_running_loop()

            # Start UDP listener
            udp_transport, _ = await loop.create_datagram_endpoint(
                lambda: SyslogProtocol(self), local_addr=(self.host, self.port)
            )
            self.udp_transport = udp_transport

            # Start TCP listener
            try:
                self.tcp_server = await asyncio.start_server(
                    self._handle_tcp_client, host=self.host, port=self.port
                )
            except Exception as tcp_err:
                logger.warning(
                    f"TCP Syslog server could not bind to {self.port}: {tcp_err}"
                )

            self.is_running = True
            self.started_at = datetime.now(UTC).isoformat()
            logger.info(
                f"Live Syslog Ingestion Listener started on {self.host}:{self.port} (UDP/TCP)."
            )
            return True
        except Exception as e:
            logger.error(f"Failed to start Syslog listener on port {self.port}: {e}")
            return False

    def stop(self) -> bool:
        if not self.is_running:
            return True

        if self.udp_transport:
            self.udp_transport.close()
            self.udp_transport = None

        if self.tcp_server:
            self.tcp_server.close()
            self.tcp_server = None

        self.is_running = False
        logger.info("Syslog Ingestion Listener stopped.")
        return True

    def get_status(self) -> dict[str, Any]:
        return {
            "is_running": self.is_running,
            "host": self.host,
            "port": self.port,
            "protocols": ["UDP", "TCP"],
            "rfc_support": ["RFC 5424", "RFC 3164", "Legacy BSD"],
            "started_at": self.started_at,
            "last_received_at": self.last_received_at,
            "stats": {
                "total_received": self.total_received,
                "total_parsed": self.total_parsed,
                "total_alerts": self.total_alerts,
                "total_errors": self.total_errors,
            },
        }


# Singleton service instance
syslog_service = SyslogService()
