import pytest
import asyncio
from app.services.syslog_service import SyslogService, SyslogProtocol

def test_syslog_service_lifecycle():
    async def _run():
        service = SyslogService(host="127.0.0.1", port=18514)
        status = service.get_status()
        assert status["is_running"] is False

        # Start
        started = await service.start()
        assert started is True
        assert service.is_running is True

        # Datagram protocol simulation
        proto = SyslogProtocol(service)
        sample_log = b'<134>1 2026-11-21T00:00:00Z web01 apache 127.0.0.1 - - [21/Nov/2026:00:00:00 +0000] "GET /index.html HTTP/1.1" 200 4096 "-" "Mozilla/5.0"'
        proto.datagram_received(sample_log, ("127.0.0.1", 18514))

        assert service.total_received == 1
        assert service.total_parsed == 1

        # Stop
        stopped = service.stop()
        assert stopped is True
        assert service.is_running is False

    asyncio.run(_run())
