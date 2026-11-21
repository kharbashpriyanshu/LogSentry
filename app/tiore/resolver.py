"""
LogSentry — Threat Intelligence Resolver & Cache Layer (TIORE Phase 3)
======================================================================
Provides sub-millisecond local intelligence resolution for extracted observables.
Evaluates in-memory thread-safe LRU cache, local threat database records,
staleness/TTL policies, and privacy gate rules before any external network activity.
"""

import threading
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.models.threat_intel import ThreatIntelRecordModel, ThreatIntelSourceModel
from app.repositories.threat_intel_repository import ThreatIntelRepository
from app.tiore.models import (
    ExtractedObservable,
    ObservableType,
    PrivacyClassification,
    ThreatClassification,
)


@dataclass
class SourceMatchEvidence:
    source_id: str
    source_name: str
    reliability_tier: int
    classification: str
    confidence: float
    threat_types: list[str]
    evidence: dict[str, Any]
    retrieved_at: str
    expires_at: str | None = None


@dataclass
class ResolvedIntelligence:
    observable_type: ObservableType
    raw_value: str
    normalized_value: str
    masked_value: str
    fingerprint: str
    classification: ThreatClassification
    confidence: float
    is_match: bool
    threat_types: list[str] = field(default_factory=list)
    verdict_reason: str = ""
    source_matches: list[dict[str, Any]] = field(default_factory=list)
    is_cached: bool = False
    cache_source: str = "none"  # "memory", "database", "privacy_gate"
    resolved_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ObservableMemoryCache:
    """
    Thread-safe, bounded LRU cache with TTL support for resolved observables.
    """

    def __init__(self, maxsize: int = 10000, ttl_seconds: int = 3600):
        self._maxsize = maxsize
        self._ttl_seconds = ttl_seconds
        self._cache: OrderedDict[str, tuple[datetime, ResolvedIntelligence]] = (
            OrderedDict()
        )
        self._lock = threading.Lock()

    def get(self, key: str) -> ResolvedIntelligence | None:
        with self._lock:
            if key not in self._cache:
                return None
            cached_at, item = self._cache[key]
            if datetime.now(UTC) - cached_at > timedelta(seconds=self._ttl_seconds):
                # Expired
                del self._cache[key]
                return None
            # Move to end (most recently accessed)
            self._cache.move_to_end(key)
            # Return copy with is_cached=True
            return item

    def set(self, key: str, item: ResolvedIntelligence) -> None:
        with self._lock:
            if key in self._cache:
                del self._cache[key]
            elif len(self._cache) >= self._maxsize:
                # Evict oldest
                self._cache.popitem(last=False)
            self._cache[key] = (datetime.now(UTC), item)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._cache)


# Global singleton in-memory cache for fast hot-path retrieval
GLOBAL_OBSERVABLE_CACHE = ObservableMemoryCache()


class IntelligenceResolver:
    """
    Local Intelligence Resolver.
    First checks in-memory cache, then checks local database repository.
    Enforces strict privacy boundaries (RFC 1918, link-local metadata, PII protection).
    """

    def __init__(self, cache: ObservableMemoryCache | None = None):
        self.cache = cache or GLOBAL_OBSERVABLE_CACHE

    def resolve(
        self,
        extracted: ExtractedObservable,
        tenant_id: str,
        db: Session,
        bypass_cache: bool = False,
    ) -> ResolvedIntelligence:
        cache_key = f"{tenant_id}:{extracted.fingerprint}"

        # 1. In-memory hot cache
        if not bypass_cache:
            cached = self.cache.get(cache_key)
            if cached is not None:
                cached.is_cached = True
                cached.cache_source = "memory"
                from app.tiore.metrics import tiore_metrics

                tiore_metrics.record_cache_hit()
                return cached
            else:
                from app.tiore.metrics import tiore_metrics

                tiore_metrics.record_cache_miss()

        # 2. Strict Privacy Gate Evaluation
        privacy_result = self._evaluate_privacy_gate(extracted)
        if privacy_result is not None:
            self.cache.set(cache_key, privacy_result)
            return privacy_result

        # 3. Database Lookup via ThreatIntelRepository (Tenant Scoped)
        repo = ThreatIntelRepository(db)
        obs_record = repo.get_observable_by_fingerprint(
            extracted.fingerprint, tenant_id=tenant_id
        )

        if not obs_record:
            # Not in local threat database -> UNKNOWN
            resolved = ResolvedIntelligence(
                observable_type=extracted.observable_type,
                raw_value=extracted.raw_value,
                normalized_value=extracted.normalized_value,
                masked_value=extracted.masked_value,
                fingerprint=extracted.fingerprint,
                classification=ThreatClassification.UNKNOWN,
                confidence=0.0,
                is_match=False,
                threat_types=[],
                verdict_reason="No local threat records found for observable.",
                source_matches=[],
                is_cached=False,
                cache_source="none",
            )
            self.cache.set(cache_key, resolved)
            return resolved

        # Observables exists in DB; fetch its threat intelligence records
        records = repo.get_records_for_fingerprint(
            extracted.fingerprint, tenant_id=tenant_id
        )
        if not records:
            resolved = ResolvedIntelligence(
                observable_type=extracted.observable_type,
                raw_value=extracted.raw_value,
                normalized_value=extracted.normalized_value,
                masked_value=extracted.masked_value,
                fingerprint=extracted.fingerprint,
                classification=ThreatClassification.BENIGN,
                confidence=0.5,
                is_match=False,
                threat_types=[],
                verdict_reason="Observable tracked in local inventory with 0 reported threats.",
                source_matches=[],
                is_cached=True,
                cache_source="database",
            )
            self.cache.set(cache_key, resolved)
            return resolved

        # Aggregate evidence from source records
        resolved = self._aggregate_records(extracted, records, db)
        self.cache.set(cache_key, resolved)
        return resolved

    def bulk_resolve(
        self,
        extracted_list: list[ExtractedObservable],
        tenant_id: str,
        db: Session,
        bypass_cache: bool = False,
    ) -> list[ResolvedIntelligence]:
        return [
            self.resolve(
                extracted, tenant_id=tenant_id, db=db, bypass_cache=bypass_cache
            )
            for extracted in extracted_list
        ]

    # -------------------------------------------------------------------------
    # Private Helpers
    # -------------------------------------------------------------------------

    def _evaluate_privacy_gate(
        self, extracted: ExtractedObservable
    ) -> ResolvedIntelligence | None:
        p_class = extracted.privacy_classification

        if p_class == PrivacyClassification.LINK_LOCAL_METADATA:
            return ResolvedIntelligence(
                observable_type=extracted.observable_type,
                raw_value=extracted.raw_value,
                normalized_value=extracted.normalized_value,
                masked_value=extracted.masked_value,
                fingerprint=extracted.fingerprint,
                classification=ThreatClassification.SUSPICIOUS,
                confidence=0.85,
                is_match=True,
                threat_types=["cloud_metadata_probe", "ssrf_target"],
                verdict_reason="Cloud instance metadata service address (169.254.169.254). Direct access frequently indicates SSRF exploitation.",
                source_matches=[],
                is_cached=True,
                cache_source="privacy_gate",
            )

        if p_class in (
            PrivacyClassification.INTERNAL_RFC1918,
            PrivacyClassification.LOOPBACK,
            PrivacyClassification.INTERNAL_DOMAIN,
        ):
            return ResolvedIntelligence(
                observable_type=extracted.observable_type,
                raw_value=extracted.raw_value,
                normalized_value=extracted.normalized_value,
                masked_value=extracted.masked_value,
                fingerprint=extracted.fingerprint,
                classification=ThreatClassification.BENIGN,
                confidence=1.0,
                is_match=False,
                threat_types=[],
                verdict_reason="Internal corporate network address or domain. Suppressed from external threat intelligence.",
                source_matches=[],
                is_cached=True,
                cache_source="privacy_gate",
            )

        if (
            p_class == PrivacyClassification.PII_SENSITIVE
            and not extracted.is_eligible_for_external_lookup
        ):
            # PII observables are suppressed from public internet lookups
            # They can only match local database records if explicitly seeded
            return None

        return None

    def _aggregate_records(
        self,
        extracted: ExtractedObservable,
        records: list[ThreatIntelRecordModel],
        db: Session,
    ) -> ResolvedIntelligence:
        now = datetime.now(UTC)
        source_matches: list[dict[str, Any]] = []
        all_threat_types: set[str] = set()

        max_confidence = 0.0
        has_malicious = False
        has_suspicious = False
        has_exposed = False
        all_stale = True

        # Fetch sources for reliability weighting
        sources = {s.id: s for s in db.query(ThreatIntelSourceModel).all()}

        for rec in records:
            # Check expiration / staleness
            is_stale = False
            if rec.expires_at:
                expires_at = (
                    rec.expires_at.replace(tzinfo=UTC)
                    if rec.expires_at.tzinfo is None
                    else rec.expires_at
                )
                if expires_at < now:
                    is_stale = True
            elif rec.retrieved_at:
                retrieved_at = (
                    rec.retrieved_at.replace(tzinfo=UTC)
                    if rec.retrieved_at.tzinfo is None
                    else rec.retrieved_at
                )
                if now - retrieved_at > timedelta(days=30):
                    is_stale = True

            if not is_stale:
                all_stale = False

            source = sources.get(rec.source_id)
            source_name = source.name if source else rec.source_id
            tier = source.reliability_tier if source else 3

            # Tier weighting: Tier 1 (1.0x), Tier 2 (0.85x), Tier 3 (0.7x)
            multiplier = 1.0 if tier == 1 else (0.85 if tier == 2 else 0.7)
            effective_conf = min(1.0, rec.confidence * multiplier)

            if effective_conf > max_confidence:
                max_confidence = effective_conf

            cls_upper = rec.classification.upper()
            if cls_upper == ThreatClassification.MALICIOUS.value:
                has_malicious = True
            elif cls_upper == ThreatClassification.SUSPICIOUS.value:
                has_suspicious = True
            elif cls_upper == ThreatClassification.EXPOSED.value:
                has_exposed = True

            for t in rec.threat_types or []:
                all_threat_types.add(t)

            evidence = SourceMatchEvidence(
                source_id=rec.source_id,
                source_name=source_name,
                reliability_tier=tier,
                classification=rec.classification,
                confidence=round(effective_conf, 2),
                threat_types=rec.threat_types or [],
                evidence=rec.evidence or {},
                retrieved_at=(
                    rec.retrieved_at.isoformat()
                    if rec.retrieved_at
                    else now.isoformat()
                ),
                expires_at=rec.expires_at.isoformat() if rec.expires_at else None,
            )
            source_matches.append(asdict(evidence))

        if all_stale and records:
            final_class = ThreatClassification.STALE
            is_match = False
            reason = f"Indicator has {len(records)} threat record(s) but all have expired/staled."
        elif has_malicious:
            final_class = ThreatClassification.MALICIOUS
            is_match = True
            reason = f"Confirmed malicious indicator across {len(source_matches)} intelligence source(s)."
        elif has_suspicious:
            final_class = ThreatClassification.SUSPICIOUS
            is_match = True
            reason = f"Suspicious activity reported across {len(source_matches)} intelligence source(s)."
        elif has_exposed:
            final_class = ThreatClassification.EXPOSED
            is_match = True
            reason = "Indicator observed in credible breach/exposure intelligence."
        else:
            final_class = ThreatClassification.BENIGN
            is_match = False
            reason = "Intelligence records report benign/clean reputation."

        return ResolvedIntelligence(
            observable_type=extracted.observable_type,
            raw_value=extracted.raw_value,
            normalized_value=extracted.normalized_value,
            masked_value=extracted.masked_value,
            fingerprint=extracted.fingerprint,
            classification=final_class,
            confidence=round(max_confidence, 2),
            is_match=is_match,
            threat_types=sorted(list(all_threat_types)),
            verdict_reason=reason,
            source_matches=source_matches,
            is_cached=True,
            cache_source="database",
        )


def seed_curated_threat_intel(db: Session) -> None:
    """
    Seeds production-grade standard threat intelligence sources and baseline curated IOCs.
    Runs idempotently during system initialization.
    """
    repo = ThreatIntelRepository(db)

    # 1. Sources
    sources_data = [
        (
            "internal_soc",
            "LogSentry SOC Curated Feed",
            "internal",
            1,
            ["ipv4", "ipv6", "domain", "url", "sha256", "email", "phone"],
        ),
        (
            "abuseipdb",
            "AbuseIPDB Threat Intelligence",
            "commercial",
            1,
            ["ipv4", "ipv6"],
        ),
        (
            "alienvault_otx",
            "AlienVault OTX Community Feed",
            "community",
            2,
            ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"],
        ),
        ("urlhaus", "abuse.ch URLhaus Feed", "open_source", 1, ["url", "domain"]),
        (
            "threatfox",
            "abuse.ch ThreatFox Feed",
            "open_source",
            1,
            ["ipv4", "domain", "url", "md5", "sha256"],
        ),
        (
            "virustotal",
            "VirusTotal Intelligence",
            "commercial",
            1,
            ["md5", "sha1", "sha256", "url", "domain", "ipv4"],
        ),
        ("hibp_prefix", "HaveIBeenPwned k-Anonymity Feed", "commercial", 2, ["email"]),
    ]

    for s_id, s_name, s_cat, s_tier, s_types in sources_data:
        repo.get_or_create_source(
            source_id=s_id,
            name=s_name,
            category=s_cat,
            reliability_tier=s_tier,
            is_enabled=True,
            supported_types=s_types,
        )

    # 2. Curated IOC Seed Data
    from app.tiore.extractor import ObservableExtractor

    extractor = ObservableExtractor()
    now = datetime.now(UTC)
    one_year_later = now + timedelta(days=365)

    curated_iocs = [
        # Known Log4Shell / Remote Exploit scanner
        {
            "raw": "45.155.205.233",
            "source_id": "abuseipdb",
            "classification": "MALICIOUS",
            "confidence": 0.98,
            "threat_types": ["exploit_scanner", "log4shell", "masscan"],
            "evidence": {
                "abuse_score": 100,
                "reports_count": 842,
                "isp": "Hostkey B.V.",
            },
        },
        # Tor Exit Node / Brute Force IP
        {
            "raw": "185.220.101.5",
            "source_id": "alienvault_otx",
            "classification": "SUSPICIOUS",
            "confidence": 0.85,
            "threat_types": ["tor_exit", "bruteforce_actor"],
            "evidence": {
                "pulse_count": 24,
                "tags": ["tor", "scanner", "ssh-bruteforce"],
            },
        },
        # C2 Phishing Domain
        {
            "raw": "threat-actor.xyz",
            "source_id": "threatfox",
            "classification": "MALICIOUS",
            "confidence": 0.95,
            "threat_types": ["c2", "cobalt_strike", "phishing"],
            "evidence": {"malware_family": "Cobalt Strike", "confidence_level": 95},
        },
        # Log4j JNDI Exploit Payload URL
        {
            "raw": "http://evil-c2.net:1389/Exploit",
            "source_id": "urlhaus",
            "classification": "MALICIOUS",
            "confidence": 0.99,
            "threat_types": ["jndi_exploit", "c2_payload"],
            "evidence": {"threat": "malware_download", "reporter": "abuse_ch"},
        },
        # WannaCry Ransomware SHA-256
        {
            "raw": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "source_id": "virustotal",
            "classification": "MALICIOUS",
            "confidence": 1.0,
            "threat_types": ["ransomware", "wannacry"],
            "evidence": {"positives": 68, "total": 70, "threat_label": "WannaCry.M"},
        },
        # Mimikatz LSASS Dump Tool SHA-256
        {
            "raw": "a324905953046f5d6bc0cc4555d3f272a80624a081ec9d77e48b3b722d99292b",
            "source_id": "internal_soc",
            "classification": "MALICIOUS",
            "confidence": 0.99,
            "threat_types": ["credential_dumping", "mimikatz", "hacktool"],
            "evidence": {
                "signature": "HackTool:Win32/Mimikatz",
                "mitre_id": "T1003.001",
            },
        },
    ]

    for item in curated_iocs:
        extracted = extractor.extract_from_text(item["raw"])
        if not extracted:
            continue
        obs_extracted = extracted[0]
        obs_record = repo.get_or_create_observable(obs_extracted, is_shared=True)
        repo.save_record(
            observable_id=obs_record.id,
            source_id=item["source_id"],
            classification=item["classification"],
            confidence=item["confidence"],
            threat_types=item["threat_types"],
            evidence=item["evidence"],
            first_reported=now,
            last_reported=now,
            expires_at=one_year_later,
        )
