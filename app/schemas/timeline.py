from datetime import datetime
from typing import Any

from pydantic import BaseModel


class TimelineEventResponse(BaseModel):
    id: str
    entity_type: str
    entity_id: str
    action: str
    actor: str | None = None
    old_value: str | None = None
    new_value: str | None = None
    metadata_json: dict[str, Any] | None = None
    created_at: datetime

    model_config = {"from_attributes": True}
