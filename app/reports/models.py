"""
Pydantic models for the Reporting module.
These models define the data structures for Executive, Technical, and Incident reports,
as well as supporting structures like TimelineEntry and ExportMetadata.
Internal implementation details are NOT exposed.
"""

import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def _now_utc() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ReportType(str, Enum):
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    INCIDENT = "incident"


class ReportStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------


class TimelineEntry(BaseModel):
    """A single chronological event in the incident timeline."""

    sequence: int = Field(..., description="Order of this event in the timeline.")
    event: str = Field(..., description="Human-readable event name.")
    description: str = Field(
        ..., description="Detailed description of what happened at this step."
    )
    timestamp: datetime = Field(
        default_factory=_now_utc, description="UTC timestamp of the event."
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional additional data for SHIELD integration.",
    )


# ---------------------------------------------------------------------------
# Export Metadata
# ---------------------------------------------------------------------------


class ExportMetadata(BaseModel):
    """Metadata attached to every exported report."""

    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    generated_at: datetime = Field(default_factory=_now_utc)
    generated_by: str = Field(default="LogSentry Reporting Engine")
    version: str = Field(default="1.0.0")
    report_type: ReportType
    export_format: str


# ---------------------------------------------------------------------------
# Executive Report
# ---------------------------------------------------------------------------


class ExecutiveReport(BaseModel):
    """High-level report suitable for management and compliance documentation."""

    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    generated_at: datetime = Field(default_factory=_now_utc)
    report_type: ReportType = ReportType.EXECUTIVE
    title: str
    executive_summary: str
    severity: str
    business_impact: str
    high_level_recommendations: list[str]
    incident_status: ReportStatus = ReportStatus.OPEN
    alert_id: str
    source_ip: str | None = None
    attack_type: str
    metadata: ExportMetadata


# ---------------------------------------------------------------------------
# Technical Report
# ---------------------------------------------------------------------------


class TechnicalReport(BaseModel):
    """Deep-dive report for SOC analysts with full technical context."""

    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    generated_at: datetime = Field(default_factory=_now_utc)
    report_type: ReportType = ReportType.TECHNICAL
    title: str
    original_log: str
    detection_rule: str
    rule_version: str
    evidence: dict[str, Any]
    threat_intelligence: list[dict[str, Any]]
    mitre_technique: str | None = None
    mitre_tactic: str | None = None
    ai_technical_analysis: str
    recommended_actions: str
    confidence_score: float
    false_positive_likelihood: str
    metadata: ExportMetadata


# ---------------------------------------------------------------------------
# Incident Report
# ---------------------------------------------------------------------------


class IncidentReport(BaseModel):
    """Comprehensive report combining executive and technical views with timeline."""

    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    generated_at: datetime = Field(default_factory=_now_utc)
    report_type: ReportType = ReportType.INCIDENT
    title: str

    # Executive Layer
    executive_summary: str
    severity: str
    business_impact: str
    incident_status: ReportStatus = ReportStatus.OPEN

    # Technical Layer
    technical_details: str
    original_log: str
    detection_rule: str
    evidence: dict[str, Any]

    # Intel & AI
    threat_intelligence: list[dict[str, Any]]
    ai_findings: str
    analyst_notes: str
    false_positive_likelihood: str
    confidence_score: float

    # Mapping
    mitre_technique: str | None = None
    mitre_tactic: str | None = None
    mitre_mapping: dict[str, str | None] = Field(default_factory=dict)

    # Timeline & IOCs
    timeline: list[TimelineEntry]
    indicators_of_compromise: list[str]

    # Recommendations
    recommendations: list[str]

    metadata: ExportMetadata
