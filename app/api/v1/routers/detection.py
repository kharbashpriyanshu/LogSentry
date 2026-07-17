from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException
from app.schemas.api import DetectionRequest, DetectionResponse
from app.schemas.log_event import LogEvent
from app.services.detection_service import DetectionService
from app.services.parsing_service import ParsingService
from app.api.dependencies import get_detection_service, get_parsing_service

router = APIRouter()

@router.post("/analyze", response_model=DetectionResponse)
def analyze_event(
    request: DetectionRequest,
    detection_service: DetectionService = Depends(get_detection_service)
):
    try:
        event = LogEvent(**request.event)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid event schema: {e}")
        
    alerts = detection_service.analyze_event(event)
    return DetectionResponse(alerts=[a.model_dump() for a in alerts])

@router.post("/analyze-file", response_model=DetectionResponse)
async def analyze_file(
    parser_name: str = Form(...),
    file: UploadFile = File(...),
    parsing_service: ParsingService = Depends(get_parsing_service),
    detection_service: DetectionService = Depends(get_detection_service)
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
        
    # Delegate to services
    _, _, _, events = await parsing_service.parse_file(parser_name, file)
    alerts = detection_service.analyze_events(events)
    
    return DetectionResponse(alerts=[a.model_dump() for a in alerts])
