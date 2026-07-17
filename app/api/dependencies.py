from fastapi import Depends
from app.services.parsing_service import ParsingService
from app.services.detection_service import DetectionService
from app.detection.engine import DetectionEngine

# Dependency Injection Singletons
_detection_engine = DetectionEngine()

def get_parsing_service() -> ParsingService:
    return ParsingService()

def get_detection_engine() -> DetectionEngine:
    return _detection_engine

def get_detection_service(engine: DetectionEngine = Depends(get_detection_engine)) -> DetectionService:
    return DetectionService(engine)
