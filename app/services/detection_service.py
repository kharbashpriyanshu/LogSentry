from app.detection.engine import DetectionEngine
from app.schemas.detection_alert import DetectionAlert
from app.schemas.log_event import LogEvent


class DetectionService:
    def __init__(self, engine: DetectionEngine):
        self.engine = engine

    def analyze_event(self, event: LogEvent) -> list[DetectionAlert]:
        return self.engine.process_event(event)

    def analyze_events(self, events: list[LogEvent]) -> list[DetectionAlert]:
        return self.engine.process_events(events)
