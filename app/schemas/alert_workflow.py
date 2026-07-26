from pydantic import BaseModel, Field
from typing import Optional, List

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
    priority: Optional[str] = None
    notes: Optional[str] = None
    assigned_by: str

class AlertInvestigate(BaseModel):
    title: str
    description: str
    priority: str
    category: str
    tags: Optional[str] = None
    investigator: str

class AlertComment(BaseModel):
    content: str
    author: str
