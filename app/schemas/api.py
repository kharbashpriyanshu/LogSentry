from pydantic import BaseModel, Field
from typing import List, Optional, Any, Dict
from datetime import datetime

# Health Models
class HealthResponse(BaseModel):
    status: str
    version: str
    uptime_seconds: float
    parsers_available: int
    detection_rules_available: int

# Parsing Models
class ParseLineRequest(BaseModel):
    parser_name: str = Field(..., description="The name of the parser to use, e.g., 'apache', 'nginx'")
    log_line: str = Field(..., description="The raw log string to parse")

class ParseResponse(BaseModel):
    success: bool
    event: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class ParseFileResponse(BaseModel):
    total_lines_processed: int
    successful_parses: int
    failed_parses: int
    events: List[Dict[str, Any]]

# Detection Models
class DetectionRequest(BaseModel):
    event: Dict[str, Any]

class DetectionResponse(BaseModel):
    alerts: List[Dict[str, Any]]

# Generic Error Model
class ErrorResponse(BaseModel):
    error: str
    details: Optional[str] = None
    correlation_id: Optional[str] = None
