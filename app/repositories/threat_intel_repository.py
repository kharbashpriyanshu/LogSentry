"""
LogSentry — Threat Intelligence Repository
==========================================
Data access layer for TIORE entities, enforcing multi-tenant isolation,
observable deduplication, threat record retention, and audit trails.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import desc, or_
from sqlalchemy.orm import Session

from app.core.crypto import encrypt_pii
from app.models.threat_intel import (
    EventObservableModel,
    ObservableModel,
    ThreatEnrichmentJobModel,
    ThreatIntelAuditModel,
    ThreatIntelMatchModel,
    ThreatIntelRecordModel,
    ThreatIntelSourceModel,
)
from app.tiore.models import ExtractedObservable, ObservableType


class ThreatIntelRepository:
    def __init__(self, db: Session):
        self.db = db

    # -------------------------------------------------------------------------
    # Observables
    # -------------------------------------------------------------------------

    def get_or_create_observable(
        self,
        extracted: ExtractedObservable,
        tenant_id: str | None = None,
        is_shared: bool = False,
        commit: bool = True,
    ) -> ObservableModel:
        """
        Finds existing observable by fingerprint or creates a new canonical entry.
        Strictly isolates tenant-owned observations from shared public threat intelligence:
        Tenant A and Tenant B observing the same indicator obtain separate tenant-scoped records.
        """
        now = datetime.now(UTC)
        is_pii = extracted.observable_type in (
            ObservableType.EMAIL,
            ObservableType.PHONE,
        )
        effective_tenant = tenant_id or "default"
        shared_flag = False if is_pii else is_shared

        query = self.db.query(ObservableModel).filter(
            ObservableModel.fingerprint == extracted.fingerprint
        )
        if shared_flag:
            query = query.filter(ObservableModel.is_shared.is_(True))
        else:
            query = query.filter(
                ObservableModel.tenant_id == effective_tenant,
                ObservableModel.is_shared.is_(False),
            )
        obs = query.first()

        if obs:
            obs.last_seen = now
            if not obs.encrypted_value and is_pii:
                obs.encrypted_value = encrypt_pii(extracted.normalized_value)
                obs.value = extracted.masked_value
            if commit:
                self.db.commit()
                self.db.refresh(obs)
            return obs

        # If PII, encrypt at rest and store masked representation in primary value column
        if is_pii:
            stored_value = extracted.masked_value
            enc_value = encrypt_pii(extracted.normalized_value)
            shared_flag = False
            assigned_tenant = effective_tenant
        else:
            stored_value = extracted.normalized_value
            enc_value = None
            assigned_tenant = None if shared_flag else effective_tenant

        obs = ObservableModel(
            id=str(uuid.uuid4()),
            tenant_id=assigned_tenant,
            is_shared=shared_flag,
            type=extracted.observable_type.value,
            value=stored_value,
            encrypted_value=enc_value,
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
        if commit:
            self.db.commit()
            self.db.refresh(obs)
        return obs

    def get_observable_by_id(
        self,
        observable_id: str,
        tenant_id: str | None = None,
        is_admin: bool = False,
    ) -> ObservableModel | None:
        """Retrieves observable by ID with strict tenant boundary enforcement."""
        query = self.db.query(ObservableModel).filter(
            ObservableModel.id == observable_id
        )
        if not is_admin and tenant_id:
            query = query.filter(
                or_(
                    ObservableModel.tenant_id == tenant_id,
                    ObservableModel.is_shared.is_(True),
                    ObservableModel.tenant_id.is_(None),
                )
            )
        return query.first()

    def get_observable_by_fingerprint(
        self,
        fingerprint: str,
        tenant_id: str | None = None,
        is_admin: bool = False,
    ) -> ObservableModel | None:
        query = self.db.query(ObservableModel).filter(
            ObservableModel.fingerprint == fingerprint
        )
        if not is_admin and tenant_id:
            query = query.filter(
                or_(
                    ObservableModel.tenant_id == tenant_id,
                    ObservableModel.is_shared.is_(True),
                    ObservableModel.tenant_id.is_(None),
                )
            )
        return query.first()

    def get_observable_by_value(
        self,
        obs_type: str,
        normalized_val: str,
        tenant_id: str | None = None,
        is_admin: bool = False,
    ) -> ObservableModel | None:
        query = self.db.query(ObservableModel).filter(
            ObservableModel.type == obs_type,
            ObservableModel.value == normalized_val,
        )
        if not is_admin and tenant_id:
            query = query.filter(
                or_(
                    ObservableModel.tenant_id == tenant_id,
                    ObservableModel.is_shared.is_(True),
                    ObservableModel.tenant_id.is_(None),
                )
            )
        return query.first()

    def get_observables_paginated(
        self,
        tenant_id: str | None = None,
        is_admin: bool = False,
        page: int = 1,
        limit: int = 50,
        obs_type: str | None = None,
    ) -> tuple[list[ObservableModel], int]:
        """Returns paginated observables filtered by tenant boundary."""
        query = self.db.query(ObservableModel)
        if not is_admin and tenant_id:
            query = query.filter(
                or_(
                    ObservableModel.tenant_id == tenant_id,
                    ObservableModel.is_shared.is_(True),
                    ObservableModel.tenant_id.is_(None),
                )
            )
        if obs_type:
            query = query.filter(ObservableModel.type == obs_type)

        total = query.count()
        items = (
            query.order_by(desc(ObservableModel.last_seen))
            .offset((page - 1) * limit)
            .limit(limit)
            .all()
        )
        return items, total

    def get_observable_count(
        self,
        tenant_id: str | None = None,
        is_admin: bool = False,
    ) -> int:
        """Returns observable count visible to the specified tenant."""
        query = self.db.query(ObservableModel)
        if not is_admin and tenant_id:
            query = query.filter(
                or_(
                    ObservableModel.tenant_id == tenant_id,
                    ObservableModel.is_shared.is_(True),
                    ObservableModel.tenant_id.is_(None),
                )
            )
        return query.count()

    # -------------------------------------------------------------------------
    # Sources
    # -------------------------------------------------------------------------

    def get_sources(self, enabled_only: bool = True) -> list[ThreatIntelSourceModel]:
        query = self.db.query(ThreatIntelSourceModel)
        if enabled_only:
            query = query.filter(ThreatIntelSourceModel.is_enabled.is_(True))
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
        source = (
            self.db.query(ThreatIntelSourceModel)
            .filter(ThreatIntelSourceModel.id == source_id)
            .first()
        )
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
        self,
        source_id: str,
        health_status: str,
        rate_limit_state: dict[str, Any] | None = None,
    ) -> None:
        source = (
            self.db.query(ThreatIntelSourceModel)
            .filter(ThreatIntelSourceModel.id == source_id)
            .first()
        )
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
        record = (
            self.db.query(ThreatIntelRecordModel)
            .filter(
                ThreatIntelRecordModel.observable_id == observable_id,
                ThreatIntelRecordModel.source_id == source_id,
            )
            .first()
        )

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

    def get_records_for_observable(
        self, observable_id: str
    ) -> list[ThreatIntelRecordModel]:
        return (
            self.db.query(ThreatIntelRecordModel)
            .filter(ThreatIntelRecordModel.observable_id == observable_id)
            .all()
        )

    def get_records_for_fingerprint(
        self,
        fingerprint: str,
        tenant_id: str | None = None,
        is_admin: bool = False,
    ) -> list[ThreatIntelRecordModel]:
        """
        Retrieves all threat intelligence records for observables matching a fingerprint
        that are accessible to the given tenant (tenant-owned or globally shared).
        """
        obs_query = self.db.query(ObservableModel.id).filter(
            ObservableModel.fingerprint == fingerprint
        )
        if not is_admin and tenant_id:
            obs_query = obs_query.filter(
                or_(
                    ObservableModel.tenant_id == tenant_id,
                    ObservableModel.is_shared.is_(True),
                    ObservableModel.tenant_id.is_(None),
                )
            )
        obs_ids = [row[0] for row in obs_query.all()]
        if not obs_ids:
            return []
        return (
            self.db.query(ThreatIntelRecordModel)
            .filter(ThreatIntelRecordModel.observable_id.in_(obs_ids))
            .all()
        )

    # -------------------------------------------------------------------------
    # Event-Observable Associations
    # -------------------------------------------------------------------------

    def link_event_observable(
        self,
        event_id: str,
        observable_id: str,
        field_name: str,
        tenant_id: str,
        commit: bool = True,
    ) -> EventObservableModel:
        # Check if already linked
        existing = (
            self.db.query(EventObservableModel)
            .filter(
                EventObservableModel.event_id == event_id,
                EventObservableModel.observable_id == observable_id,
                EventObservableModel.field_name == field_name,
            )
            .first()
        )
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
        if commit:
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
        commit: bool = True,
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
        if commit:
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
        query = self.db.query(ThreatIntelMatchModel).filter(
            ThreatIntelMatchModel.id == match_id
        )
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

    # -------------------------------------------------------------------------
    # Durable Asynchronous Threat Enrichment Jobs (Issue E)
    # -------------------------------------------------------------------------

    def enqueue_enrichment_job(
        self,
        observable_id: str,
        observable_value: str,
        observable_type: str,
        tenant_id: str,
        event_id: str | None = None,
        alert_id: str | None = None,
        commit: bool = True,
    ) -> ThreatEnrichmentJobModel:
        """
        Enqueues an external enrichment job with deduplication against active jobs.
        """
        existing = (
            self.db.query(ThreatEnrichmentJobModel)
            .filter(
                ThreatEnrichmentJobModel.observable_id == observable_id,
                ThreatEnrichmentJobModel.tenant_id == tenant_id,
                ThreatEnrichmentJobModel.status.in_(["pending", "processing"]),
            )
            .first()
        )
        if existing:
            return existing

        now = datetime.now(UTC)
        job = ThreatEnrichmentJobModel(
            id=str(uuid.uuid4()),
            observable_id=observable_id,
            observable_value=observable_value,
            observable_type=observable_type,
            tenant_id=tenant_id,
            status="pending",
            attempts=0,
            max_attempts=3,
            event_id=event_id,
            alert_id=alert_id,
            created_at=now,
            updated_at=now,
        )
        self.db.add(job)
        if commit:
            self.db.commit()
            self.db.refresh(job)
        return job

    def get_pending_enrichment_jobs(
        self, limit: int = 20
    ) -> list[ThreatEnrichmentJobModel]:
        """Fetches pending enrichment jobs for execution."""
        return (
            self.db.query(ThreatEnrichmentJobModel)
            .filter(ThreatEnrichmentJobModel.status == "pending")
            .order_by(ThreatEnrichmentJobModel.created_at.asc())
            .limit(limit)
            .all()
        )

    def mark_enrichment_job_processing(self, job_id: str) -> bool:
        job = (
            self.db.query(ThreatEnrichmentJobModel)
            .filter(ThreatEnrichmentJobModel.id == job_id)
            .first()
        )
        if not job or job.status != "pending":
            return False
        job.status = "processing"
        job.attempts += 1
        job.updated_at = datetime.now(UTC)
        self.db.commit()
        return True

    def mark_enrichment_job_completed(self, job_id: str) -> bool:
        job = (
            self.db.query(ThreatEnrichmentJobModel)
            .filter(ThreatEnrichmentJobModel.id == job_id)
            .first()
        )
        if not job:
            return False
        job.status = "completed"
        job.updated_at = datetime.now(UTC)
        self.db.commit()
        return True

    def mark_enrichment_job_failed(self, job_id: str, error_message: str) -> bool:
        job = (
            self.db.query(ThreatEnrichmentJobModel)
            .filter(ThreatEnrichmentJobModel.id == job_id)
            .first()
        )
        if not job:
            return False
        job.last_error = error_message[:1000]
        job.updated_at = datetime.now(UTC)
        if job.attempts < job.max_attempts:
            job.status = "pending"  # Retry
        else:
            job.status = "failed"
        self.db.commit()
        return True
