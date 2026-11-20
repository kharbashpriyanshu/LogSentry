from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException
from app.schemas.api import DetectionRequest, DetectionResponse
from app.schemas.log_event import LogEvent
from app.schemas.detection_alert import DetectionAlert
from app.services.detection_service import DetectionService
from app.services.parsing_service import ParsingService
from app.api.dependencies import get_detection_service, get_parsing_service, get_alert_repository, get_log_event_repository
from app.repositories.alert_repository import AlertRepository
from app.repositories.log_event_repository import LogEventRepository

from typing import List, Dict, Any
from app.detection.registry import RuleRegistry
from app.detection.yaml_rule import YamlDetectionRule, YamlRuleLoader

router = APIRouter()

@router.get("/rules", response_model=List[Dict[str, Any]])
def list_detection_rules():
    """List all registered detection rules, including native and dynamic Sigma/YAML rules."""
    rules = RuleRegistry.get_all_rules()
    results = []
    for r in rules:
        results.append({
            "name": r.rule_name,
            "title": r.title,
            "version": r.rule_version,
            "description": r.description,
            "severity": r.severity.value,
            "attack_type": r.attack_type,
            "mitre_technique": r.mitre_technique,
            "mitre_tactic": r.mitre_tactic,
            "risk_score": r.risk_score,
            "format": "sigma/yaml" if isinstance(r, YamlDetectionRule) else "python"
        })
    return results

@router.post("/rules/reload")
def reload_dynamic_rules():
    """Reload all dynamic YAML / Sigma rules from the rules/ directory."""
    loaded = YamlRuleLoader.load_directory("rules")
    return {
        "status": "success",
        "message": f"Successfully reloaded {len(loaded)} dynamic YAML/Sigma rules.",
        "rules": [r.rule_name for r in loaded]
    }

@router.post("/analyze", response_model=DetectionResponse)
def analyze_event(
    request: DetectionRequest,
    detection_service: DetectionService = Depends(get_detection_service),
    alert_repo: AlertRepository = Depends(get_alert_repository),
    event_repo: LogEventRepository = Depends(get_log_event_repository)
):
    try:
        event = LogEvent(**request.event)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid event schema: {e}")
        
    event_model = event_repo.create_event(event)
    alerts = detection_service.analyze_event(event)
    for alert in alerts:
        alert_repo.create_alert(alert)
    return DetectionResponse(alerts=[a.model_dump() for a in alerts])

@router.post("/detect", response_model=DetectionAlert)
def detect_single_event(
    request: DetectionRequest,
    detection_service: DetectionService = Depends(get_detection_service),
    alert_repo: AlertRepository = Depends(get_alert_repository),
    event_repo: LogEventRepository = Depends(get_log_event_repository)
):
    try:
        event = LogEvent(**request.event)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid event schema: {e}")
        
    event_model = event_repo.create_event(event)
    alerts = detection_service.analyze_event(event)
    if not alerts:
        raise HTTPException(status_code=404, detail="No alerts generated for this event.")
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
    event_repo: LogEventRepository = Depends(get_log_event_repository)
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
