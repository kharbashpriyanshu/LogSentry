import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.severity import Severity


def default_timestamp():
    return datetime.now(UTC)


class DetectionAlert(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=default_timestamp)
    rule_name: str
    rule_version: str
    severity: Severity
    confidence: float
    risk_score: float
    title: str
    description: str
    source_ip: str | None = None
    destination_ip: str | None = None
    endpoint: str | None = None
    attack_type: str
    mitre_technique: str | None = None
    mitre_tactic: str | None = None
    recommendation: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    raw_log_reference: str
    status: str = "OPEN"
    assignee: str | None = None
    assignment_notes: str | None = None
    resolved_at: datetime | None = None
    resolution_type: str | None = None
    resolution_note: str | None = None
    false_positive_reason: str | None = None
    hostname: str | None = None
    tenant_id: str | None = "default"
