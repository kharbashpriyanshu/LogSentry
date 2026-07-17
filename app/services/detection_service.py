from typing import List
from app.schemas.log_event import LogEvent
from app.schemas.detection_alert import DetectionAlert
from app.detection.engine import DetectionEngine

class DetectionService:
    def __init__(self, engine: DetectionEngine):
        self.engine = engine
        
    def analyze_event(self, event: LogEvent) -> List[DetectionAlert]:
        return self.engine.process_event(event)

    def analyze_events(self, events: List[LogEvent]) -> List[DetectionAlert]:
        return self.engine.process_events(events)
