"""
LogSentry — Threat Intelligence & Observable Reputation Engine (TIORE) Models
=============================================================================
SQLAlchemy models providing local IOC database persistence, source tracking,
event associations, match correlation, and privacy audit logs with multi-tenant isolation.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from app.database.base import Base


class ObservableModel(Base):
    """
    Core canonical observable entity.
    Stores normalized value, analyst-safe masked value, and deterministic fingerprint.
    Public indicators use standard SHA-256 fingerprints; PII indicators (emails, phones)
    use keyed HMAC-SHA256 to prevent dictionary inversion attacks.
    """

    __tablename__ = "threat_observables"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(64), nullable=True, index=True)
    is_shared = Column(Boolean, nullable=False, default=False, index=True)
    type = Column(String(32), nullable=False, index=True)
    value = Column(String(2048), nullable=False, index=True)
    encrypted_value = Column(Text, nullable=True)
    raw_masked = Column(String(2048), nullable=False)
    fingerprint = Column(String(64), unique=True, nullable=False, index=True)
    validation_status = Column(String(32), nullable=False, default="valid")
    privacy_classification = Column(
        String(32), nullable=False, default="public_routable"
    )
    is_eligible_for_external_lookup = Column(Boolean, nullable=False, default=False)
    metadata_json = Column("metadata", JSON, nullable=True)
    first_seen = Column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    last_seen = Column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    records = relationship(
        "ThreatIntelRecordModel",
        back_populates="observable",
        cascade="all, delete-orphan",
    )
    matches = relationship(
        "ThreatIntelMatchModel",
        back_populates="observable",
        cascade="all, delete-orphan",
    )
    event_links = relationship(
        "EventObservableModel",
        back_populates="observable",
        cascade="all, delete-orphan",
    )


class ThreatIntelSourceModel(Base):
    """
    Threat intelligence provider and local feed registry.
    Tracks provider capabilities, health, reliability tiers, and API quota state.
    """

    __tablename__ = "threat_sources"

    id = Column(
        String(64), primary_key=True
    )  # e.g. 'abuseipdb', 'otx', 'urlhaus', 'local_curated'
    name = Column(String(128), nullable=False)
    category = Column(String(64), nullable=False)
    reliability_tier = Column(
        Integer, nullable=False, default=3
    )  # 1 (low) to 5 (authoritative)
    is_enabled = Column(Boolean, nullable=False, default=True)
    supported_types = Column(JSON, nullable=True)
    rate_limit_state = Column(JSON, nullable=True)
    last_sync = Column(DateTime(timezone=True), nullable=True)
    health_status = Column(String(32), nullable=False, default="healthy")

    records = relationship(
        "ThreatIntelRecordModel", back_populates="source", cascade="all, delete-orphan"
    )


class ThreatIntelRecordModel(Base):
    """
    Individual threat intelligence assertion/record for an observable from a specific source.
    Stores classification, confidence, threat categories, and detailed provider evidence.
    """

    __tablename__ = "threat_records"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    observable_id = Column(
        String(36),
        ForeignKey("threat_observables.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_id = Column(
        String(64),
        ForeignKey("threat_sources.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    classification = Column(
        String(32), nullable=False, index=True
    )  # MALICIOUS, SUSPICIOUS, EXPOSED, BENIGN, UNKNOWN
    confidence = Column(Float, nullable=False, default=0.0)
    threat_types = Column(
        JSON, nullable=True
    )  # e.g. ["brute_force", "c2", "ransomware", "phishing"]
    evidence = Column(JSON, nullable=True)
    raw_payload = Column(JSON, nullable=True)
    first_reported = Column(DateTime(timezone=True), nullable=True)
    last_reported = Column(DateTime(timezone=True), nullable=True)
    retrieved_at = Column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    expires_at = Column(DateTime(timezone=True), nullable=True)

    observable = relationship("ObservableModel", back_populates="records")
    source = relationship("ThreatIntelSourceModel", back_populates="records")


class EventObservableModel(Base):
    """
    Relational association linking log events to extracted observables.
    Strictly scoped by tenant_id to prevent cross-tenant telemetry exposure.
    """

    __tablename__ = "event_observables"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id = Column(
        String,
        ForeignKey("log_events.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    observable_id = Column(
        String(36),
        ForeignKey("threat_observables.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    field_name = Column(String(64), nullable=False)
    tenant_id = Column(String(64), nullable=False, default="default", index=True)
    created_at = Column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    observable = relationship("ObservableModel", back_populates="event_links")


class ThreatIntelMatchModel(Base):
    """
    Correlated match record generated when an event observable matches known threat intelligence.
    Enriched with final consensus verdict, confidence, alert/incident associations, and analyst triage workflow.
    """

    __tablename__ = "threat_matches"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    observable_id = Column(
        String(36),
        ForeignKey("threat_observables.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_id = Column(
        String,
        ForeignKey("log_events.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    alert_id = Column(
        String, ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True, index=True
    )
    incident_id = Column(
        String,
        ForeignKey("incidents.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    classification = Column(String(32), nullable=False, index=True)
    confidence = Column(Float, nullable=False, default=0.0)
    verdict_reason = Column(String(512), nullable=False)
    tenant_id = Column(String(64), nullable=False, default="default", index=True)
    review_status = Column(String(32), nullable=False, default="unreviewed")
    reviewed_by = Column(String(64), nullable=True)
    analyst_notes = Column(Text, nullable=True)
    matched_at = Column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    observable = relationship("ObservableModel", back_populates="matches")


class ThreatIntelAuditModel(Base):
    """
    Security audit log capturing every manual or automated observable lookup,
    especially sensitive PII inquiries, recording whether external network disclosure occurred.
    """

    __tablename__ = "threat_intel_audits"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    actor_id = Column(String(64), nullable=False)
    actor_username = Column(String(64), nullable=False)
    actor_role = Column(String(32), nullable=False)
    tenant_id = Column(String(64), nullable=False, default="default", index=True)
    observable_type = Column(String(32), nullable=False)
    masked_value = Column(String(255), nullable=False)
    fingerprint = Column(String(64), nullable=False, index=True)
    lookup_method = Column(String(32), nullable=False)
    external_disclosed = Column(Boolean, nullable=False, default=False)
    disclosed_to = Column(JSON, nullable=True)
    timestamp = Column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
