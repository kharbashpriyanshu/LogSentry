from pydantic import BaseModel


class AlertFalsePositive(BaseModel):
    reason: str
    notes: str
    marked_by: str


class AlertResolve(BaseModel):
    resolution_type: str
    notes: str
    resolved_by: str


class AlertAssign(BaseModel):
    assignee: str
    priority: str | None = None
    notes: str | None = None
    assigned_by: str


class AlertInvestigate(BaseModel):
    title: str
    description: str
    priority: str
    category: str
    tags: str | None = None
    investigator: str


class AlertComment(BaseModel):
    content: str
    author: str
