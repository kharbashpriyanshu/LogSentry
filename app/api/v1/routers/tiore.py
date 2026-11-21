"""
LogSentry — TIORE Threat Intelligence API Router (TIORE Phase 7)
================================================================
Exposes manual investigation endpoints, observable inventory, match triage,
feed source telemetry, and audit compliance logs for SOC teams.
"""

from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.dependencies import get_threat_intel_repository
from app.core.rbac import (
    UserContext,
    UserRole,
    get_current_user,
    require_role,
)
from app.database.session import get_db
from app.repositories.threat_intel_repository import ThreatIntelRepository
from app.tiore.engine import tiore_engine
from app.tiore.models import ObservableType, ThreatClassification

router = APIRouter()


class IndicatorLookupRequest(BaseModel):
    indicator: str = Field(..., min_length=2, max_length=2048, description="IP, Domain, URL, Hash, Email, or Phone")
    force_external: bool = Field(False, description="Whether to query configured external threat intelligence feeds")


class MatchReviewRequest(BaseModel):
    review_status: str = Field(..., description="under_review, confirmed_threat, false_positive, benign_exception")
    notes: str | None = Field(None, max_length=1000)


@router.post("/lookup")
def lookup_indicator(
    request: IndicatorLookupRequest,
    user: UserContext = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Performs manual observable investigation, evaluates reputation,
    records audit evidence, and protects sensitive PII.
    """
    result = tiore_engine.investigate_indicator(
        indicator_raw=request.indicator,
        tenant_id=user.tenant_id,
        actor_id=user.user_id,
        actor_username=user.username,
        actor_role=user.role.value,
        db=db,
        force_external=request.force_external,
    )
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result.get("message"))
    return result


@router.get("/matches")
def get_threat_matches(
    classification: str | None = Query(None, description="MALICIOUS, SUSPICIOUS, EXPOSED"),
    limit: int = Query(50, ge=1, le=200),
    user: UserContext = Depends(get_current_user),
    repo: ThreatIntelRepository = Depends(get_threat_intel_repository),
):
    """
    Returns threat matches detected across logs and alerts, scoped by tenant.
    """
    is_admin = user.role == UserRole.ADMIN
    matches = repo.get_matches(
        tenant_id=user.tenant_id,
        is_admin=is_admin,
        limit=limit,
        classification=classification,
    )
    return [
        {
            "id": m.id,
            "observable_id": m.observable_id,
            "observable_value": m.observable.value if m.observable else None,
            "observable_type": m.observable.type if m.observable else None,
            "raw_masked": m.observable.raw_masked if m.observable else None,
            "classification": m.classification,
            "confidence": m.confidence,
            "verdict_reason": m.verdict_reason,
            "event_id": m.event_id,
            "alert_id": m.alert_id,
            "incident_id": m.incident_id,
            "review_status": m.review_status,
            "reviewed_by": m.reviewed_by,
            "analyst_notes": m.analyst_notes,
            "tenant_id": m.tenant_id,
            "matched_at": m.matched_at.isoformat() if m.matched_at else None,
        }
        for m in matches
    ]


@router.patch("/matches/{match_id}/review")
def review_match(
    match_id: str,
    request: MatchReviewRequest,
    user: UserContext = Depends(require_role(UserRole.TIER_1_ANALYST, UserRole.TIER_2_ANALYST, UserRole.SOC_MANAGER, UserRole.ADMIN)),
    repo: ThreatIntelRepository = Depends(get_threat_intel_repository),
):
    """
    Triage and review an identified threat match.
    """
    valid_statuses = ("unreviewed", "under_review", "confirmed_threat", "false_positive", "benign_exception")
    if request.review_status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid review_status. Allowed: {valid_statuses}")

    is_admin = user.role == UserRole.ADMIN
    updated = repo.update_match_review(
        match_id=match_id,
        tenant_id=user.tenant_id,
        review_status=request.review_status,
        reviewed_by=user.username,
        notes=request.notes,
        is_admin=is_admin,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Threat match not found or access denied.")

    return {
        "status": "success",
        "match_id": updated.id,
        "review_status": updated.review_status,
        "reviewed_by": updated.reviewed_by,
        "notes": updated.analyst_notes,
    }


@router.get("/observables")
def get_observables(
    obs_type: str | None = Query(None, description="ipv4, domain, url, sha256, etc."),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    user: UserContext = Depends(get_current_user),
    repo: ThreatIntelRepository = Depends(get_threat_intel_repository),
):
    """
    Returns inventory of tracked canonical observables.
    """
    items, total = repo.get_observables_paginated(page=page, limit=limit, obs_type=obs_type)
    return {
        "items": [
            {
                "id": o.id,
                "type": o.type,
                "value": o.value,
                "raw_masked": o.raw_masked,
                "fingerprint": o.fingerprint,
                "validation_status": o.validation_status,
                "privacy_classification": o.privacy_classification,
                "is_eligible_for_external_lookup": o.is_eligible_for_external_lookup,
                "first_seen": o.first_seen.isoformat() if o.first_seen else None,
                "last_seen": o.last_seen.isoformat() if o.last_seen else None,
            }
            for o in items
        ],
        "total": total,
        "page": page,
        "limit": limit,
    }


@router.get("/sources")
def get_sources(
    user: UserContext = Depends(get_current_user),
    repo: ThreatIntelRepository = Depends(get_threat_intel_repository),
):
    """
    Returns configured threat intelligence sources and their live health/rate limit status.
    """
    sources = repo.get_sources(enabled_only=False)
    return [
        {
            "id": s.id,
            "name": s.name,
            "category": s.category,
            "reliability_tier": s.reliability_tier,
            "is_enabled": s.is_enabled,
            "health_status": s.health_status,
            "supported_types": s.supported_types,
            "rate_limit_state": s.rate_limit_state,
            "last_sync": s.last_sync.isoformat() if s.last_sync else None,
        }
        for s in sources
    ]


@router.get("/audit")
def get_audits(
    limit: int = Query(50, ge=1, le=200),
    user: UserContext = Depends(get_current_user),
    repo: ThreatIntelRepository = Depends(get_threat_intel_repository),
):
    """
    Returns audit trail of manual indicator investigations, tenant-scoped.
    """
    is_admin = user.role == UserRole.ADMIN
    audits = repo.get_audits(tenant_id=user.tenant_id, is_admin=is_admin, limit=limit)
    return [
        {
            "id": a.id,
            "actor_id": a.actor_id,
            "actor_username": a.actor_username,
            "actor_role": a.actor_role,
            "tenant_id": a.tenant_id,
            "observable_type": a.observable_type,
            "masked_value": a.masked_value,
            "lookup_method": a.lookup_method,
            "external_disclosed": a.external_disclosed,
            "disclosed_to": a.disclosed_to,
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
        }
        for a in audits
    ]


@router.get("/stats")
def get_stats(
    user: UserContext = Depends(get_current_user),
    db: Session = Depends(get_db),
    repo: ThreatIntelRepository = Depends(get_threat_intel_repository),
):
    """
    High-level dashboard KPIs for Threat Intelligence Center.
    """
    from app.models.threat_intel import ObservableModel, ThreatIntelMatchModel

    is_admin = user.role == UserRole.ADMIN
    match_query = db.query(ThreatIntelMatchModel)
    if not is_admin:
        match_query = match_query.filter(ThreatIntelMatchModel.tenant_id == user.tenant_id)

    total_matches = match_query.count()
    malicious_matches = match_query.filter(ThreatIntelMatchModel.classification == "MALICIOUS").count()
    suspicious_matches = match_query.filter(ThreatIntelMatchModel.classification == "SUSPICIOUS").count()
    exposed_matches = match_query.filter(ThreatIntelMatchModel.classification == "EXPOSED").count()
    unreviewed_matches = match_query.filter(ThreatIntelMatchModel.review_status == "unreviewed").count()

    total_observables = db.query(ObservableModel).count()
    sources = repo.get_sources(enabled_only=False)
    healthy_sources = sum(1 for s in sources if s.health_status == "healthy")

    return {
        "total_observables": total_observables,
        "total_matches": total_matches,
        "malicious_matches": malicious_matches,
        "suspicious_matches": suspicious_matches,
        "exposed_matches": exposed_matches,
        "unreviewed_matches": unreviewed_matches,
        "total_sources": len(sources),
        "healthy_sources": healthy_sources,
    }
