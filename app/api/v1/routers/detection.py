from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException
from app.schemas.api import DetectionRequest, DetectionResponse
from app.schemas.log_event import LogEvent
from app.schemas.detection_alert import DetectionAlert
from app.services.detection_service import DetectionService
from app.services.parsing_service import ParsingService
from app.api.dependencies import get_detection_service, get_parsing_service, get_alert_repository, get_log_event_repository
from app.repositories.alert_repository import AlertRepository
from app.repositories.log_event_repository import LogEventRepository

router = APIRouter()

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
