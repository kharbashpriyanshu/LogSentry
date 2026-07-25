from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class ContainmentAction(BaseModel):
    priority: str = Field(..., description="Immediate, High, Medium, or Low")
    action: str = Field(..., description="Action to take")
    reason: str = Field(..., description="Reasoning for this action")

class AttackStage(BaseModel):
    stage: str = Field(..., description="Name of the attack stage (e.g. Initial Access)")
    evidence: str = Field(..., description="Evidence found in the telemetry")
    confidence: float = Field(..., description="Confidence score from 0.0 to 1.0")

class AIAnalysisResponse(BaseModel):
    executive_summary: str = Field(..., description="High level summary of the event.")
    technical_explanation: str = Field(..., description="Deep dive into the mechanics of the attack.")
    severity_justification: str = Field(..., description="Reasoning behind the severity rating.")
    likely_attack_goal: str = Field(..., description="What the attacker is trying to achieve.")
    potential_impact: str = Field(..., description="What happens if the attack succeeds.")
    recommended_actions: str = Field(..., description="General remediation steps for the security team.")
    containment_strategy: List[ContainmentAction] = Field(default_factory=list, description="Specific containment steps to isolate the threat.")
    attack_chain: List[AttackStage] = Field(default_factory=list, description="The progression of the attack identified.")
    cve_references: List[str] = Field(default_factory=list, description="List of CVEs identified. DO NOT invent CVEs. Return empty list if none are certain.")
    mitre_technique: Optional[str] = Field(None, description="Identified MITRE ATT&CK technique ID.")
    confidence_score: float = Field(..., description="Confidence from 0.0 to 1.0.")
    false_positive_likelihood: str = Field(..., description="High, Medium, or Low.")
    analyst_notes: str = Field(..., description="Short blurb mimicking human analyst notes.")
