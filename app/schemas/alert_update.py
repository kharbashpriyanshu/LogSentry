from pydantic import BaseModel, Field
from typing import Optional

class AlertUpdate(BaseModel):
    status: Optional[str] = None
    assignee: Optional[str] = None
    severity: Optional[str] = None
    resolution_note: Optional[str] = None
