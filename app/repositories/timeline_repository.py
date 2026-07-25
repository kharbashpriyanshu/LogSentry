from sqlalchemy.orm import Session
from app.models.timeline import TimelineEventModel
from app.schemas.timeline import TimelineEventResponse
from typing import List, Optional

class TimelineRepository:
    def __init__(self, db: Session):
        self.db = db

    def add_event(self, entity_type: str, entity_id: str, action: str, actor: Optional[str] = None, old_value: Optional[str] = None, new_value: Optional[str] = None, metadata_json: dict = None) -> TimelineEventResponse:
        model = TimelineEventModel(
            entity_type=entity_type,
            entity_id=entity_id,
            action=action,
            actor=actor,
            old_value=old_value,
            new_value=new_value,
            metadata_json=metadata_json
        )
        self.db.add(model)
        self.db.commit()
        self.db.refresh(model)
        return TimelineEventResponse.model_validate(model)

    def get_events(self, entity_type: str, entity_id: str) -> List[TimelineEventResponse]:
        models = self.db.query(TimelineEventModel).filter(
            TimelineEventModel.entity_type == entity_type,
            TimelineEventModel.entity_id == entity_id
        ).order_by(TimelineEventModel.created_at.asc()).all()
        return [TimelineEventResponse.model_validate(m) for m in models]
