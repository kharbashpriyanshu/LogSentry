from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


def default_timestamp():
    return datetime.now(UTC)


class ThreatEnrichment(BaseModel):
    provider: str = Field(..., description="Name of the enrichment provider")
    reputation: str | None = Field(
        None, description="General reputation (e.g., malicious, suspicious, clean)"
    )
    confidence: float | None = Field(
        None, description="Confidence score from the provider"
    )
    country: str | None = Field(None, description="Country code of IP")
    isp: str | None = Field(None, description="ISP of IP")
    pulse_count: int | None = Field(None, description="Number of OTX pulses")
    mitre_technique: str | None = Field(
        None, description="Mapped MITRE ATT&CK technique"
    )
    mitre_tactic: str | None = Field(None, description="Mapped MITRE ATT&CK tactic")
    ioc_tags: list[str] = Field(
        default_factory=list, description="Tags associated with the IOC"
    )
    references: list[str] = Field(
        default_factory=list, description="Links to external reports/references"
    )
    timestamp: datetime = Field(
        default_factory=default_timestamp, description="Time of enrichment"
    )


class ProviderStatus(BaseModel):
    name: str
    status: str
    score: float | None = None
    latency: float | None = None


class RiskScore(BaseModel):
    score: int
    level: str


class GeoData(BaseModel):
    country: str | None = None
    countryCode: str | None = None
    isp: str | None = None


class NormalizedThreatIntel(BaseModel):
    observable: str
    observable_type: str
    risk: RiskScore
    reputation: dict[str, Any] = Field(default_factory=dict)
    geo: GeoData
    providers: list[ProviderStatus]
    mitre: list[str] = Field(default_factory=list)
    ioc_tags: list[str] = Field(default_factory=list)
    cached: bool = False
    enriched_at: datetime = Field(default_factory=default_timestamp)
