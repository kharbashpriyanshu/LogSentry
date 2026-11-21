from datetime import datetime

from pydantic import BaseModel


class LogEvent(BaseModel):
    timestamp: datetime | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    method: str | None = None
    endpoint: str | None = None
    protocol: str | None = None
    status_code: int | None = None
    response_size: int | None = None
    user_agent: str | None = None
    hostname: str | None = None
    raw_log: str
    parser_name: str
    # Enterprise & Multi-Source Telemetry Fields
    user: str | None = None
    event_id: str | None = None
    action: str | None = None
    process_name: str | None = None
    command_line: str | None = None
    tenant_id: str | None = "default"
