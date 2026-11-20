import asyncio
import logging
import re
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from app.parsers.factory import ParserFactory
from app.detection.engine import DetectionEngine
from app.services.soar_service import SOARService
from app.services.websocket import ConnectionManager

logger = logging.getLogger(__name__)

# Regex to strip RFC 3164 / 5424 headers like <134>1 2026-11-21T... or <13>Jul 26 10:00:00 host app:
_SYSLOG_HEADER_REGEX = re.compile(r"^<\d+>(?:\d\s+)?(?:\S+\s+){1,4}")

class SyslogProtocol(asyncio.DatagramProtocol):
    """Async UDP Protocol for receiving RFC 3164 / 5424 syslog streams."""

    def __init__(self, service: "SyslogService"):
        self.service = service
        self.parser_factory = ParserFactory
        self.engine = DetectionEngine()

    def datagram_received(self, data: bytes, addr):
        raw_msg = data.decode("utf-8", errors="ignore").strip()
        if not raw_msg:
            return

        self.service.total_received += 1
        self.service.last_received_at = datetime.now(timezone.utc).isoformat()

        # Clean syslog framing: locate start of actual access log payload
        clean_msg = raw_msg
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\s+[-a-zA-Z0-9_]+\s+", raw_msg)
        if ip_match:
            clean_msg = raw_msg[ip_match.start():].strip()
        elif "<" in raw_msg and ">" in raw_msg:
            clean_msg = re.sub(r"^<\d+>(?:\d\s+)?", "", raw_msg).strip()

        try:
            # Attempt to guess or use Apache parser
            try:
                parser = self.parser_factory.guess_parser(clean_msg)
            except Exception:
                parser = self.parser_factory.get_parser("apache")

            event = parser.parse_line(clean_msg)
            if event:
                self.service.total_parsed += 1
                # If source IP wasn't in log, use UDP sender address
                if not event.source_ip and addr:
                    event.source_ip = addr[0]

                alerts = self.engine.process_event(event)
                if alerts:
                    self.service.total_alerts += len(alerts)
                    for alert in alerts:
                        # Auto-containment evaluation
                        SOARService.evaluate_auto_containment(alert)
                        # Broadcast in background
                        try:
                            loop = asyncio.get_running_loop()
                            loop.create_task(
                                ConnectionManager.broadcast_event(
                                    "new_alert",
                                    alert.model_dump(mode="json")
                                )
                            )
                        except Exception:
                            pass
        except Exception as e:
            self.service.total_errors += 1
            logger.error(f"Error processing syslog message from {addr}: {e}")


class SyslogService:
    """Manager for the live background Syslog ingestion listener."""

    def __init__(self, host: str = "0.0.0.0", port: int = 1514):
        self.host = host
        self.port = port
        self.is_running = False
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.total_received = 0
        self.total_parsed = 0
        self.total_alerts = 0
        self.total_errors = 0
        self.started_at: Optional[str] = None
        self.last_received_at: Optional[str] = None

    async def start(self) -> bool:
        if self.is_running:
            return True

        try:
            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(
                lambda: SyslogProtocol(self),
                local_addr=(self.host, self.port)
            )
            self.transport = transport
            self.is_running = True
            self.started_at = datetime.now(timezone.utc).isoformat()
            logger.info(f"Syslog listener active on udp://{self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"Failed to start Syslog listener on port {self.port}: {e}")
            return False

    def stop(self) -> bool:
        if self.transport and self.is_running:
            self.transport.close()
            self.is_running = False
            logger.info("Syslog listener stopped.")
            return True
        return False

    def get_status(self) -> Dict[str, Any]:
        return {
            "is_running": self.is_running,
            "host": self.host,
            "port": self.port,
            "started_at": self.started_at,
            "last_received_at": self.last_received_at,
            "metrics": {
                "total_received": self.total_received,
                "total_parsed": self.total_parsed,
                "total_alerts": self.total_alerts,
                "total_errors": self.total_errors
            }
        }

# Global singleton
syslog_service = SyslogService()
