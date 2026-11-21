from pydantic import BaseModel


class AlertUpdate(BaseModel):
    status: str | None = None
    assignee: str | None = None
    severity: str | None = None
    resolution_note: str | None = None
