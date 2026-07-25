from sqlalchemy.orm import Session
from app.models.log_event import LogEventModel
from app.schemas.log_event import LogEvent

class LogEventRepository:
    def __init__(self, db: Session):
        self.db = db

    def create_event(self, event: LogEvent) -> LogEventModel:
        model = LogEventModel(
            timestamp=event.timestamp,
            source=event.hostname,
            source_type=event.parser_name,
            raw_log=event.raw_log,
            parsed_data=event.model_dump(mode='json'),
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            http_method=event.method,
            path=event.endpoint,
            status_code=str(event.status_code) if event.status_code else None
        )
        self.db.add(model)
        self.db.commit()
        self.db.refresh(model)
        return model
