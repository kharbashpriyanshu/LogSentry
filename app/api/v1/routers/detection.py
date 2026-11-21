from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.api.dependencies import (
    get_alert_repository,
    get_detection_service,
    get_log_event_repository,
    get_parsing_service,
)
from app.core.rbac import (
    UserContext,
    UserRole,
    get_authenticated_agent_or_user,
    get_current_user,
    require_role,
)
from app.database.session import get_db
from app.detection.correlation import correlation_engine
from app.detection.registry import RuleRegistry
from app.detection.yaml_rule import YamlDetectionRule, YamlRuleLoader
from app.repositories.alert_repository import AlertRepository
from app.repositories.log_event_repository import LogEventRepository
from app.schemas.api import (
    BatchDetectionRequest,
    BatchDetectionResponse,
    DetectionRequest,
    DetectionResponse,
)
from app.schemas.detection_alert import DetectionAlert
from app.schemas.log_event import LogEvent
from app.services.dedup_service import event_deduplicator
from app.services.detection_service import DetectionService
from app.services.parsing_service import ParsingService
from app.tiore.engine import tiore_engine

router = APIRouter()


@router.get("/rules", response_model=list[dict[str, Any]])
def list_detection_rules():
    """List all registered detection rules, including native and dynamic Sigma/YAML rules."""
    rules = RuleRegistry.get_all_rules()
    results = []
    for r in rules:
        results.append(
            {
                "name": r.rule_name,
                "title": r.title,
                "version": r.rule_version,
                "description": r.description,
                "severity": r.severity.value,
                "attack_type": r.attack_type,
                "mitre_technique": r.mitre_technique,
                "mitre_tactic": r.mitre_tactic,
                "risk_score": r.risk_score,
                "format": (
                    "sigma/yaml" if isinstance(r, YamlDetectionRule) else "python"
                ),
            }
        )
    return results


@router.post("/rules/reload")
def reload_dynamic_rules(
    user: UserContext = Depends(require_role(UserRole.ADMIN, UserRole.SOC_MANAGER)),
):
    """Reload all dynamic YAML / Sigma rules from the rules/ directory. Requires Admin/SOC_Manager."""
    loaded = YamlRuleLoader.load_directory("rules")
    return {
        "status": "success",
        "message": f"Successfully reloaded {len(loaded)} dynamic YAML/Sigma rules.",
        "rules": [r.rule_name for r in loaded],
    }


@router.post("/analyze", response_model=DetectionResponse)
def analyze_event(
    request: DetectionRequest,
    principal: UserContext = Depends(get_authenticated_agent_or_user),
    detection_service: DetectionService = Depends(get_detection_service),
    alert_repo: AlertRepository = Depends(get_alert_repository),
    event_repo: LogEventRepository = Depends(get_log_event_repository),
    db: Session = Depends(get_db),
):
    try:
        event = LogEvent(**request.event)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid event schema: {e}")

    # Enforce tenant boundary
    if principal.role != UserRole.ADMIN or not getattr(event, "tenant_id", None):
        event.tenant_id = principal.tenant_id

    event_repo.create_event(event)
    alerts = detection_service.analyze_event(event)
    first_alert_id = None
    for alert in alerts:
        if not getattr(alert, "tenant_id", None):
            alert.tenant_id = event.tenant_id
        alert_repo.create_alert(alert)
        if not first_alert_id:
            first_alert_id = getattr(alert, "alert_id", None) or getattr(alert, "id", None)

    # TIORE: Synchronous observable extraction & local threat matching
    try:
        tiore_engine.process_event_observables(
            event_id=str(getattr(event, "event_id", None) or event.timestamp),
            event_data=event.model_dump(),
            tenant_id=event.tenant_id,
            db=db,
            alert_id=first_alert_id,
        )
    except Exception:
        pass

    return DetectionResponse(alerts=[a.model_dump() for a in alerts])


@router.post("/detect", response_model=DetectionAlert)
def detect_single_event(
    request: DetectionRequest,
    principal: UserContext = Depends(get_authenticated_agent_or_user),
    detection_service: DetectionService = Depends(get_detection_service),
    alert_repo: AlertRepository = Depends(get_alert_repository),
    event_repo: LogEventRepository = Depends(get_log_event_repository),
    db: Session = Depends(get_db),
):
    try:
        event = LogEvent(**request.event)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid event schema: {e}")

    # Enforce tenant boundary
    if principal.role != UserRole.ADMIN or not getattr(event, "tenant_id", None):
        event.tenant_id = principal.tenant_id

    event_repo.create_event(event)
    alerts = detection_service.analyze_event(event)
    if not alerts:
        raise HTTPException(
            status_code=404, detail="No alerts generated for this event."
        )
    for alert in alerts:
        if not getattr(alert, "tenant_id", None):
            alert.tenant_id = event.tenant_id
        alert_repo.create_alert(alert)

    # TIORE: Synchronous observable extraction & local threat matching
    try:
        tiore_engine.process_event_observables(
            event_id=str(getattr(event, "event_id", None) or event.timestamp),
            event_data=event.model_dump(),
            tenant_id=event.tenant_id,
            db=db,
            alert_id=getattr(alerts[0], "alert_id", None) or getattr(alerts[0], "id", None),
        )
    except Exception:
        pass

    return alerts[0]


@router.post("/analyze-file", response_model=DetectionResponse)
async def analyze_file(
    parser_name: str = Form(...),
    file: UploadFile = File(...),
    user: UserContext = Depends(get_current_user),
    parsing_service: ParsingService = Depends(get_parsing_service),
    detection_service: DetectionService = Depends(get_detection_service),
    alert_repo: AlertRepository = Depends(get_alert_repository),
    event_repo: LogEventRepository = Depends(get_log_event_repository),
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    # Delegate to services
    _, _, _, events = await parsing_service.parse_file(parser_name, file)
    all_alerts = []
    for event in events:
        if user.role != UserRole.ADMIN or not getattr(event, "tenant_id", None):
            event.tenant_id = user.tenant_id
        event_repo.create_event(event)
        alerts = detection_service.analyze_event(event)
        for alert in alerts:
            if not getattr(alert, "tenant_id", None):
                alert.tenant_id = event.tenant_id
            alert_repo.create_alert(alert)
            all_alerts.append(alert)

    return DetectionResponse(alerts=[a.model_dump() for a in all_alerts])


@router.post("/batch", response_model=BatchDetectionResponse)
def analyze_batch(
    request: BatchDetectionRequest,
    principal: UserContext = Depends(get_authenticated_agent_or_user),
    detection_service: DetectionService = Depends(get_detection_service),
    alert_repo: AlertRepository = Depends(get_alert_repository),
    event_repo: LogEventRepository = Depends(get_log_event_repository),
    db: Session = Depends(get_db),
):
    """
    High-throughput batch ingestion endpoint with idempotent deduplication and real-time attack correlation.
    Returns acknowledgements (ack_ids) so telemetry shippers can safely clear persistent local spools.
    Enforces strict tenant assignment based on authenticated agent / user identity.
    """
    ack_ids: list[str] = []
    rejected_errors: list[dict[str, str]] = []
    processed_count = 0
    duplicate_count = 0
    rejected_count = 0
    alerts_generated = 0
    active_campaigns = []

    # Enforce tenant scoping: agents and non-admins cannot write to arbitrary tenants
    enforced_tenant = principal.tenant_id
    if principal.role == UserRole.ADMIN and request.tenant_id:
        enforced_tenant = request.tenant_id

    for raw_item in request.events:
        item_id = str(raw_item.get("event_id") or raw_item.get("id") or "")
        # Ensure tenant_id in raw_item matches enforced tenant
        raw_item["tenant_id"] = enforced_tenant
        fingerprint = event_deduplicator.compute_event_fingerprint(raw_item)
        effective_id = item_id or fingerprint

        if event_deduplicator.check_duplicate(fingerprint):
            duplicate_count += 1
            ack_ids.append(effective_id)
            continue

        # Normalize parser name
        if not raw_item.get("parser_name"):
            raw_item["parser_name"] = raw_item.get("source_type") or "generic"

        try:
            if not raw_item.get("timestamp"):
                from datetime import UTC, datetime

                raw_item["timestamp"] = datetime.now(UTC).isoformat()
            event = LogEvent(**raw_item)
            event.tenant_id = enforced_tenant
        except Exception as exc:
            # Malformed item: reject explicitly so shipper/client knows it failed
            rejected_count += 1
            rejected_errors.append(
                {"event_id": effective_id, "error": f"Schema validation failed: {exc}"}
            )
            continue

        try:
            event_repo.create_event(event)
        except Exception as exc:
            rejected_count += 1
            rejected_errors.append(
                {"event_id": effective_id, "error": f"Persistence failed: {exc}"}
            )
            continue

        # Successfully validated and persisted — safe to record in deduplication cache
        event_deduplicator.record_seen(fingerprint)
        ack_ids.append(getattr(event, "event_id", None) or effective_id)
        processed_count += 1

        alerts = detection_service.analyze_event(event)
        for alert in alerts:
            alert_repo.create_alert(alert)
            alerts_generated += 1

            # Real-time event correlation
            campaign = correlation_engine.correlate_alert(alert)
            if campaign and campaign not in active_campaigns:
                active_campaigns.append(campaign)

        # TIORE: Synchronous observable extraction & local threat matching
        try:
            tiore_engine.process_event_observables(
                event_id=str(getattr(event, "event_id", None) or effective_id),
                event_data=event.model_dump(),
                tenant_id=event.tenant_id,
                db=db,
                alert_id=getattr(alerts[0], "alert_id", None) or getattr(alerts[0], "id", None) if alerts else None,
            )
        except Exception:
            pass

    return BatchDetectionResponse(
        status="acknowledged" if rejected_count == 0 else "partial_success",
        received_count=len(request.events),
        processed_count=processed_count,
        duplicate_count=duplicate_count,
        rejected_count=rejected_count,
        alerts_generated=alerts_generated,
        ack_ids=ack_ids,
        rejected_errors=rejected_errors,
        correlated_campaigns=[
            {
                "campaign_id": c.campaign_id,
                "tenant_id": getattr(c, "tenant_id", "default"),
                "title": c.title,
                "severity": c.severity,
                "confidence": c.confidence,
                "summary": c.summary,
                "tactics": c.tactics,
                "alert_count": len(c.alert_ids),
            }
            for c in active_campaigns
        ],
    )
