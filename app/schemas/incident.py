from datetime import datetime

from pydantic import BaseModel, Field


class IncidentBase(BaseModel):
    title: str
    description: str | None = None
    severity: str
    priority: str | None = None
    category: str | None = None
    tags: str | None = None


class IncidentCreate(IncidentBase):
    alert_ids: list[str] = Field(default_factory=list)


class IncidentUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: str | None = None
    priority: str | None = None
    category: str | None = None
    tags: str | None = None
    status: str | None = None
    assignee: str | None = None
    add_alert_ids: list[str] | None = None


class IncidentResponse(IncidentBase):
    id: str
    status: str
    assignee: str | None = None
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None = None
    alert_ids: list[str] = Field(default_factory=list)

    model_config = {"from_attributes": True}
