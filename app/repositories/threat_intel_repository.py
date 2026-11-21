"""
LogSentry — Threat Intelligence Repository
==========================================
Data access layer for TIORE entities, enforcing multi-tenant isolation,
observable deduplication, threat record retention, and audit trails.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.models.threat_intel import (
    EventObservableModel,
    ObservableModel,
    ThreatIntelAuditModel,
    ThreatIntelMatchModel,
    ThreatIntelRecordModel,
    ThreatIntelSourceModel,
)
from app.tiore.models import ExtractedObservable


class ThreatIntelRepository:
    def __init__(self, db: Session):
        self.db = db

    # -------------------------------------------------------------------------
    # Observables
    # -------------------------------------------------------------------------

    def get_or_create_observable(self, extracted: ExtractedObservable) -> ObservableModel:
        """Finds existing observable by fingerprint or creates a new canonical entry."""
        obs = self.db.query(ObservableModel).filter(
            ObservableModel.fingerprint == extracted.fingerprint
        ).first()

        now = datetime.now(UTC)
        if obs:
            obs.last_seen = now
            self.db.commit()
            self.db.refresh(obs)
            return obs

        obs = ObservableModel(
            id=str(uuid.uuid4()),
            type=extracted.observable_type.value,
            value=extracted.normalized_value,
            raw_masked=extracted.masked_value,
            fingerprint=extracted.fingerprint,
            validation_status=extracted.validation_status.value,
            privacy_classification=extracted.privacy_classification.value,
            is_eligible_for_external_lookup=extracted.is_eligible_for_external_lookup,
            metadata_json=extracted.metadata,
            first_seen=now,
            last_seen=now,
        )
        self.db.add(obs)
        self.db.commit()
        self.db.refresh(obs)
        return obs

    def get_observable_by_fingerprint(self, fingerprint: str) -> ObservableModel | None:
        return self.db.query(ObservableModel).filter(
            ObservableModel.fingerprint == fingerprint
        ).first()

    def get_observable_by_value(self, obs_type: str, normalized_val: str) -> ObservableModel | None:
        return self.db.query(ObservableModel).filter(
            ObservableModel.type == obs_type,
            ObservableModel.value == normalized_val,
        ).first()

    def get_observables_paginated(
        self,
        page: int = 1,
        limit: int = 50,
        obs_type: str | None = None,
    ) -> tuple[list[ObservableModel], int]:
        query = self.db.query(ObservableModel)
        if obs_type:
            query = query.filter(ObservableModel.type == obs_type)

        total = query.count()
        items = query.order_by(desc(ObservableModel.last_seen)).offset((page - 1) * limit).limit(limit).all()
        return items, total

    # -------------------------------------------------------------------------
    # Sources
    # -------------------------------------------------------------------------

    def get_sources(self, enabled_only: bool = True) -> list[ThreatIntelSourceModel]:
        query = self.db.query(ThreatIntelSourceModel)
        if enabled_only:
            query = query.filter(ThreatIntelSourceModel.is_enabled == True)  # noqa: E712
        return query.all()

    def get_or_create_source(
        self,
        source_id: str,
        name: str,
        category: str,
        reliability_tier: int = 3,
        is_enabled: bool = True,
        supported_types: list[str] | None = None,
    ) -> ThreatIntelSourceModel:
        source = self.db.query(ThreatIntelSourceModel).filter(
            ThreatIntelSourceModel.id == source_id
        ).first()
        if source:
            return source

        source = ThreatIntelSourceModel(
            id=source_id,
            name=name,
            category=category,
            reliability_tier=reliability_tier,
            is_enabled=is_enabled,
            supported_types=supported_types or [],
            health_status="healthy",
        )
        self.db.add(source)
        self.db.commit()
        self.db.refresh(source)
        return source

    def update_source_health(
        self, source_id: str, health_status: str, rate_limit_state: dict[str, Any] | None = None
    ) -> None:
        source = self.db.query(ThreatIntelSourceModel).filter(
            ThreatIntelSourceModel.id == source_id
        ).first()
        if source:
            source.health_status = health_status
            if rate_limit_state is not None:
                source.rate_limit_state = rate_limit_state
            source.last_sync = datetime.now(UTC)
            self.db.commit()

    # -------------------------------------------------------------------------
    # Threat Records
    # -------------------------------------------------------------------------

    def save_record(
        self,
        observable_id: str,
        source_id: str,
        classification: str,
        confidence: float,
        threat_types: list[str] | None = None,
        evidence: dict[str, Any] | None = None,
        raw_payload: dict[str, Any] | None = None,
        first_reported: datetime | None = None,
        last_reported: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> ThreatIntelRecordModel:
        # Check if record from this source already exists for this observable
        record = self.db.query(ThreatIntelRecordModel).filter(
            ThreatIntelRecordModel.observable_id == observable_id,
            ThreatIntelRecordModel.source_id == source_id,
        ).first()

        now = datetime.now(UTC)
        if record:
            record.classification = classification
            record.confidence = confidence
            record.threat_types = threat_types or []
            record.evidence = evidence or {}
            record.raw_payload = raw_payload or {}
            if first_reported:
                record.first_reported = first_reported
            if last_reported:
                record.last_reported = last_reported
            record.retrieved_at = now
            record.expires_at = expires_at
        else:
            record = ThreatIntelRecordModel(
                id=str(uuid.uuid4()),
                observable_id=observable_id,
                source_id=source_id,
                classification=classification,
                confidence=confidence,
                threat_types=threat_types or [],
                evidence=evidence or {},
                raw_payload=raw_payload or {},
                first_reported=first_reported,
                last_reported=last_reported,
                retrieved_at=now,
                expires_at=expires_at,
            )
            self.db.add(record)

        self.db.commit()
        self.db.refresh(record)
        return record

    def get_records_for_observable(self, observable_id: str) -> list[ThreatIntelRecordModel]:
        return self.db.query(ThreatIntelRecordModel).filter(
            ThreatIntelRecordModel.observable_id == observable_id
        ).all()

    # -------------------------------------------------------------------------
    # Event-Observable Associations
    # -------------------------------------------------------------------------

    def link_event_observable(
        self, event_id: str, observable_id: str, field_name: str, tenant_id: str
    ) -> EventObservableModel:
        # Check if already linked
        existing = self.db.query(EventObservableModel).filter(
            EventObservableModel.event_id == event_id,
            EventObservableModel.observable_id == observable_id,
            EventObservableModel.field_name == field_name,
        ).first()
        if existing:
            return existing

        link = EventObservableModel(
            id=str(uuid.uuid4()),
            event_id=event_id,
            observable_id=observable_id,
            field_name=field_name,
            tenant_id=tenant_id,
            created_at=datetime.now(UTC),
        )
        self.db.add(link)
        self.db.commit()
        self.db.refresh(link)
        return link

    # -------------------------------------------------------------------------
    # Threat Matches (Tenant-Scoped)
    # -------------------------------------------------------------------------

    def create_match(
        self,
        observable_id: str,
        classification: str,
        confidence: float,
        verdict_reason: str,
        tenant_id: str,
        event_id: str | None = None,
        alert_id: str | None = None,
        incident_id: str | None = None,
    ) -> ThreatIntelMatchModel:
        match = ThreatIntelMatchModel(
            id=str(uuid.uuid4()),
            observable_id=observable_id,
            event_id=event_id,
            alert_id=alert_id,
            incident_id=incident_id,
            classification=classification,
            confidence=confidence,
            verdict_reason=verdict_reason,
            tenant_id=tenant_id,
            review_status="unreviewed",
            matched_at=datetime.now(UTC),
        )
        self.db.add(match)
        self.db.commit()
        self.db.refresh(match)
        return match

    def get_matches(
        self,
        tenant_id: str,
        is_admin: bool = False,
        limit: int = 50,
        classification: str | None = None,
    ) -> list[ThreatIntelMatchModel]:
        query = self.db.query(ThreatIntelMatchModel)
        if not is_admin:
            query = query.filter(ThreatIntelMatchModel.tenant_id == tenant_id)

        if classification:
            query = query.filter(ThreatIntelMatchModel.classification == classification)

        return query.order_by(desc(ThreatIntelMatchModel.matched_at)).limit(limit).all()

    def get_match_by_id(
        self, match_id: str, tenant_id: str, is_admin: bool = False
    ) -> ThreatIntelMatchModel | None:
        query = self.db.query(ThreatIntelMatchModel).filter(ThreatIntelMatchModel.id == match_id)
        if not is_admin:
            query = query.filter(ThreatIntelMatchModel.tenant_id == tenant_id)
        return query.first()

    def update_match_review(
        self,
        match_id: str,
        tenant_id: str,
        review_status: str,
        reviewed_by: str,
        notes: str | None = None,
        is_admin: bool = False,
    ) -> ThreatIntelMatchModel | None:
        match = self.get_match_by_id(match_id, tenant_id, is_admin=is_admin)
        if not match:
            return None

        match.review_status = review_status
        match.reviewed_by = reviewed_by
        if notes:
            match.analyst_notes = notes

        self.db.commit()
        self.db.refresh(match)
        return match

    # -------------------------------------------------------------------------
    # Audit Trail (Tenant-Scoped)
    # -------------------------------------------------------------------------

    def record_audit(
        self,
        actor_id: str,
        actor_username: str,
        actor_role: str,
        tenant_id: str,
        observable_type: str,
        masked_value: str,
        fingerprint: str,
        lookup_method: str,
        external_disclosed: bool = False,
        disclosed_to: list[str] | None = None,
    ) -> ThreatIntelAuditModel:
        audit = ThreatIntelAuditModel(
            id=str(uuid.uuid4()),
            actor_id=actor_id,
            actor_username=actor_username,
            actor_role=actor_role,
            tenant_id=tenant_id,
            observable_type=observable_type,
            masked_value=masked_value,
            fingerprint=fingerprint,
            lookup_method=lookup_method,
            external_disclosed=external_disclosed,
            disclosed_to=disclosed_to or [],
            timestamp=datetime.now(UTC),
        )
        self.db.add(audit)
        self.db.commit()
        self.db.refresh(audit)
        return audit

    def get_audits(
        self, tenant_id: str, is_admin: bool = False, limit: int = 50
    ) -> list[ThreatIntelAuditModel]:
        query = self.db.query(ThreatIntelAuditModel)
        if not is_admin:
            query = query.filter(ThreatIntelAuditModel.tenant_id == tenant_id)
        return query.order_by(desc(ThreatIntelAuditModel.timestamp)).limit(limit).all()
