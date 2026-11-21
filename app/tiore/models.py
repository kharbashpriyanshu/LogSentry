from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ObservableType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    PHONE = "phone"


class ValidationStatus(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    AMBIGUOUS = "ambiguous"
    PRIVATE_SUPPRESSED = "private_suppressed"


class PrivacyClassification(str, Enum):
    PUBLIC_ROUTABLE = "public_routable"
    INTERNAL_RFC1918 = "internal_rfc1918"
    LOOPBACK = "loopback"
    LINK_LOCAL_METADATA = "link_local_metadata"
    INTERNAL_DOMAIN = "internal_domain"
    PII_SENSITIVE = "pii_sensitive"


class ThreatClassification(str, Enum):
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    EXPOSED = "EXPOSED"
    BENIGN = "BENIGN"
    UNKNOWN = "UNKNOWN"
    STALE = "STALE"


class ExtractedObservable(BaseModel):
    """
    Standardized extracted observable representation across LogSentry.
    Ensures strict privacy tracking, normalized representation, and source provenance.
    """

    observable_type: ObservableType
    raw_value: str
    normalized_value: str
    masked_value: str
    fingerprint: str = Field(
        ..., description="Keyed HMAC for PII, SHA-256 for public indicators"
    )
    source_field: str = Field(
        ..., description="Field in event or log where indicator was discovered"
    )
    validation_status: ValidationStatus = ValidationStatus.VALID
    privacy_classification: PrivacyClassification = (
        PrivacyClassification.PUBLIC_ROUTABLE
    )
    is_eligible_for_external_lookup: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)
