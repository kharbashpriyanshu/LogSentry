from datetime import datetime, timezone
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from app.schemas.severity import Severity
import uuid

def default_timestamp():
    return datetime.now(timezone.utc)

class DetectionAlert(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=default_timestamp)
    rule_name: str
    rule_version: str
    severity: Severity
    confidence: float
    risk_score: float
    title: str
    description: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    endpoint: Optional[str] = None
    attack_type: str
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    recommendation: Optional[str] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    raw_log_reference: str
