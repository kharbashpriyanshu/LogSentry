from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from app.api.dependencies import (
    get_alert_repository,
    get_detection_service,
    get_log_event_repository,
    get_parsing_service,
)
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
def reload_dynamic_rules():
    """Reload all dynamic YAML / Sigma rules from the rules/ directory."""
    loaded = YamlRuleLoader.load_directory("rules")
    return {
        "status": "success",
        "message": f"Successfully reloaded {len(loaded)} dynamic YAML/Sigma rules.",
        "rules": [r.rule_name for r in loaded],
    }


@router.post("/analyze", response_model=DetectionResponse)
def analyze_event(
    request: DetectionRequest,
    detection_service: DetectionService = Depends(get_detection_service),
    alert_repo: AlertRepository = Depends(get_alert_repository),
    event_repo: LogEventRepository = Depends(get_log_event_repository),
):
    try:
        event = LogEvent(**request.event)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid event schema: {e}")

    event_repo.create_event(event)
    alerts = detection_service.analyze_event(event)
    for alert in alerts:
        alert_repo.create_alert(alert)
    return DetectionResponse(alerts=[a.model_dump() for a in alerts])


@router.post("/detect", response_model=DetectionAlert)
def detect_single_event(
    request: DetectionRequest,
    detection_service: DetectionService = Depends(get_detection_service),
    alert_repo: AlertRepository = Depends(get_alert_repository),
    event_repo: LogEventRepository = Depends(get_log_event_repository),
):
    try:
        event = LogEvent(**request.event)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid event schema: {e}")

    event_repo.create_event(event)
    alerts = detection_service.analyze_event(event)
    if not alerts:
        raise HTTPException(
            status_code=404, detail="No alerts generated for this event."
        )
    for alert in alerts:
        alert_repo.create_alert(alert)
    return alerts[0]


@router.post("/analyze-file", response_model=DetectionResponse)
async def analyze_file(
    parser_name: str = Form(...),
    file: UploadFile = File(...),
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
        event_repo.create_event(event)
        alerts = detection_service.analyze_event(event)
        for alert in alerts:
            alert_repo.create_alert(alert)
            all_alerts.append(alert)

    return DetectionResponse(alerts=[a.model_dump() for a in all_alerts])


@router.post("/batch", response_model=BatchDetectionResponse)
def analyze_batch(
    request: BatchDetectionRequest,
    detection_service: DetectionService = Depends(get_detection_service),
    alert_repo: AlertRepository = Depends(get_alert_repository),
    event_repo: LogEventRepository = Depends(get_log_event_repository),
):
    """
    High-throughput batch ingestion endpoint with idempotent deduplication and real-time attack correlation.
    Returns acknowledgements (ack_ids) so telemetry shippers can safely clear persistent local spools.
    """
    ack_ids: list[str] = []
    processed_count = 0
    duplicate_count = 0
    alerts_generated = 0
    active_campaigns = []

    for raw_item in request.events:
        fingerprint = event_deduplicator.compute_event_fingerprint(raw_item)
        if event_deduplicator.is_duplicate(fingerprint):
            duplicate_count += 1
            ack_ids.append(raw_item.get("event_id") or fingerprint)
            continue

        # Normalize parser name
        if not raw_item.get("parser_name"):
            raw_item["parser_name"] = raw_item.get("source_type") or "generic"

        try:
            event = LogEvent(**raw_item)
            if request.tenant_id and not getattr(event, "tenant_id", None):
                event.tenant_id = request.tenant_id
        except Exception:
            # Skip unparseable items but acknowledge receipt
            ack_ids.append(raw_item.get("event_id") or fingerprint)
            continue

        event_repo.create_event(event)
        ack_ids.append(getattr(event, "event_id", None) or fingerprint)
        processed_count += 1

        alerts = detection_service.analyze_event(event)
        for alert in alerts:
            alert_repo.create_alert(alert)
            alerts_generated += 1

            # Real-time event correlation
            campaign = correlation_engine.correlate_alert(alert)
            if campaign and campaign not in active_campaigns:
                active_campaigns.append(campaign)

    return BatchDetectionResponse(
        status="acknowledged",
        received_count=len(request.events),
        processed_count=processed_count,
        duplicate_count=duplicate_count,
        alerts_generated=alerts_generated,
        ack_ids=ack_ids,
        correlated_campaigns=[
            {
                "campaign_id": c.campaign_id,
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
