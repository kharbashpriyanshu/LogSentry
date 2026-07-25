from pydantic import BaseModel
from typing import Optional, Any, Dict
from datetime import datetime

class TimelineEventResponse(BaseModel):
    id: str
    entity_type: str
    entity_id: str
    action: str
    actor: Optional[str] = None
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    metadata_json: Optional[Dict[str, Any]] = None
    created_at: datetime

    model_config = {"from_attributes": True}
