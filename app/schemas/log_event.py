from datetime import datetime
from typing import Optional
from pydantic import BaseModel

class LogEvent(BaseModel):
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    method: Optional[str] = None
    endpoint: Optional[str] = None
    protocol: Optional[str] = None
    status_code: Optional[int] = None
    response_size: Optional[int] = None
    user_agent: Optional[str] = None
    hostname: Optional[str] = None
    raw_log: str
    parser_name: str
