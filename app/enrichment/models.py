from pydantic import BaseModel, Field
from typing import Optional, List, Dict
from datetime import datetime, timezone

def default_timestamp():
    return datetime.now(timezone.utc)

class ThreatEnrichment(BaseModel):
    provider: str = Field(..., description="Name of the enrichment provider")
    reputation: Optional[str] = Field(None, description="General reputation (e.g., malicious, suspicious, clean)")
    confidence: Optional[float] = Field(None, description="Confidence score from the provider")
    country: Optional[str] = Field(None, description="Country code of IP")
    isp: Optional[str] = Field(None, description="ISP of IP")
    pulse_count: Optional[int] = Field(None, description="Number of OTX pulses")
    mitre_technique: Optional[str] = Field(None, description="Mapped MITRE ATT&CK technique")
    mitre_tactic: Optional[str] = Field(None, description="Mapped MITRE ATT&CK tactic")
    ioc_tags: List[str] = Field(default_factory=list, description="Tags associated with the IOC")
    references: List[str] = Field(default_factory=list, description="Links to external reports/references")
    timestamp: datetime = Field(default_factory=default_timestamp, description="Time of enrichment")
