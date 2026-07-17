from pydantic import BaseModel, Field
from typing import Optional

class AIAnalysisResponse(BaseModel):
    executive_summary: str = Field(..., description="High level summary of the event.")
    technical_explanation: str = Field(..., description="Deep dive into the mechanics of the attack.")
    severity_justification: str = Field(..., description="Reasoning behind the severity rating.")
    likely_attack_goal: str = Field(..., description="What the attacker is trying to achieve.")
    potential_impact: str = Field(..., description="What happens if the attack succeeds.")
    recommended_actions: str = Field(..., description="Remediation steps for the security team.")
    mitre_technique: Optional[str] = Field(None, description="Identified MITRE ATT&CK technique.")
    confidence_score: float = Field(..., description="Confidence from 0.0 to 1.0.")
    false_positive_likelihood: str = Field(..., description="High, Medium, or Low.")
    analyst_notes: str = Field(..., description="Short blurb mimicking human analyst notes.")
