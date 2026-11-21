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
