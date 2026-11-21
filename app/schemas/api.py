from typing import Any

from pydantic import BaseModel, Field


# Health Models
class HealthResponse(BaseModel):
    status: str
    version: str
    uptime_seconds: float
    parsers_available: int
    detection_rules_available: int


# Parsing Models
class ParseLineRequest(BaseModel):
    parser_name: str = Field(
        ..., description="The name of the parser to use, e.g., 'apache', 'nginx'"
    )
    log_line: str = Field(..., description="The raw log string to parse")


class ParseResponse(BaseModel):
    success: bool
    event: dict[str, Any] | None = None
    error: str | None = None


class ParseFileResponse(BaseModel):
    total_lines_processed: int
    successful_parses: int
    failed_parses: int
    events: list[dict[str, Any]]


# Detection Models
class DetectionRequest(BaseModel):
    event: dict[str, Any]


class DetectionResponse(BaseModel):
    alerts: list[dict[str, Any]]


# Generic Error Model
class ErrorResponse(BaseModel):
    error: str
    details: str | None = None
    correlation_id: str | None = None
