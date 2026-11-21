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


class BatchDetectionRequest(BaseModel):
    events: list[dict[str, Any]] = Field(
        ..., description="Batch array of telemetry log events"
    )
    tenant_id: str = Field("default", description="Tenant workspace identifier")
    agent_id: str | None = Field(
        None, description="Registered agent or shipper identifier"
    )


class BatchDetectionResponse(BaseModel):
    status: str = "acknowledged"
    received_count: int
    processed_count: int
    duplicate_count: int
    alerts_generated: int
    ack_ids: list[str]
    correlated_campaigns: list[dict[str, Any]] = Field(default_factory=list)


# Generic Error Model
class ErrorResponse(BaseModel):
    error: str
    details: str | None = None
    correlation_id: str | None = None
