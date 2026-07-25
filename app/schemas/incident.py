from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
import uuid

class IncidentBase(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str
    priority: Optional[str] = None

class IncidentCreate(IncidentBase):
    alert_ids: List[str] = Field(default_factory=list)

class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    priority: Optional[str] = None
    status: Optional[str] = None
    assignee: Optional[str] = None
    add_alert_ids: Optional[List[str]] = None

class IncidentResponse(IncidentBase):
    id: str
    status: str
    assignee: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    alert_ids: List[str] = Field(default_factory=list)

    model_config = {"from_attributes": True}
