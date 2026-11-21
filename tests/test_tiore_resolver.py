"""
LogSentry — TIORE Phase 3 Tests: Local Intelligence Resolver & Cache Layer
==========================================================================
Verifies memory cache LRU, TTL, privacy gate enforcement, local DB resolution,
and curated seed intelligence without external network calls.
"""

from datetime import UTC, datetime, timedelta
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.base import Base
from app.models.threat_intel import ThreatIntelRecordModel, ThreatIntelSourceModel
from app.repositories.threat_intel_repository import ThreatIntelRepository
from app.tiore.extractor import ObservableExtractor
from app.tiore.models import ObservableType, PrivacyClassification, ThreatClassification
from app.tiore.resolver import (
    IntelligenceResolver,
    ObservableMemoryCache,
    ResolvedIntelligence,
    seed_curated_threat_intel,
)


@pytest.fixture
def tiore_db_session():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_memory_cache_lru_and_ttl():
    cache = ObservableMemoryCache(maxsize=3, ttl_seconds=1)

    dummy_item = ResolvedIntelligence(
        observable_type=ObservableType.IPV4,
        raw_value="1.1.1.1",
        normalized_value="1.1.1.1",
        masked_value="1.1.1.1",
        fingerprint="fp1",
        classification=ThreatClassification.BENIGN,
        confidence=1.0,
        is_match=False,
    )

    cache.set("key1", dummy_item)
    cache.set("key2", dummy_item)
    cache.set("key3", dummy_item)
    assert cache.size() == 3

    # Access key1 so key2 becomes oldest
    assert cache.get("key1") is not None

    # Add 4th item -> key2 should be evicted
    cache.set("key4", dummy_item)
    assert cache.size() == 3
    assert cache.get("key2") is None
    assert cache.get("key1") is not None
    assert cache.get("key4") is not None

    # Test clear
    cache.clear()
    assert cache.size() == 0


def test_resolver_privacy_gate_rfc1918(tiore_db_session):
    extractor = ObservableExtractor()
    resolver = IntelligenceResolver(cache=ObservableMemoryCache())

    # RFC 1918 internal IP
    extracted = extractor.extract_from_text("Alert on internal IP 192.168.1.50")[0]
    resolved = resolver.resolve(extracted, tenant_id="tenant-alpha", db=tiore_db_session)

    assert resolved.classification == ThreatClassification.BENIGN
    assert resolved.confidence == 1.0
    assert resolved.is_match is False
    assert resolved.cache_source == "privacy_gate"
    assert "Internal corporate network" in resolved.verdict_reason


def test_resolver_privacy_gate_link_local_metadata(tiore_db_session):
    extractor = ObservableExtractor()
    resolver = IntelligenceResolver(cache=ObservableMemoryCache())

    # Cloud metadata service target
    extracted = extractor.extract_from_text("curl http://169.254.169.254/latest/meta-data")[0]
    resolved = resolver.resolve(extracted, tenant_id="tenant-alpha", db=tiore_db_session)

    assert resolved.classification == ThreatClassification.SUSPICIOUS
    assert resolved.is_match is True
    assert "ssrf_target" in resolved.threat_types
    assert resolved.cache_source == "privacy_gate"
    assert "169.254.169.254" in resolved.verdict_reason


def test_resolver_unknown_observable(tiore_db_session):
    extractor = ObservableExtractor()
    resolver = IntelligenceResolver(cache=ObservableMemoryCache())

    extracted = extractor.extract_from_text("Connection from 93.184.216.34")[0]
    resolved = resolver.resolve(extracted, tenant_id="tenant-alpha", db=tiore_db_session)

    assert resolved.classification == ThreatClassification.UNKNOWN
    assert resolved.confidence == 0.0
    assert resolved.is_match is False
    assert len(resolved.source_matches) == 0


def test_resolver_seed_curated_intel_and_match(tiore_db_session):
    extractor = ObservableExtractor()
    resolver = IntelligenceResolver(cache=ObservableMemoryCache())

    # Seed curated intel
    seed_curated_threat_intel(tiore_db_session)

    # 1. Test known Log4Shell scanner IP
    extracted_ip = extractor.extract_from_text("Attack payload from 45.155.205.233")[0]
    resolved_ip = resolver.resolve(extracted_ip, tenant_id="tenant-alpha", db=tiore_db_session)

    assert resolved_ip.classification == ThreatClassification.MALICIOUS
    assert resolved_ip.is_match is True
    assert resolved_ip.confidence >= 0.9
    assert "log4shell" in resolved_ip.threat_types
    assert len(resolved_ip.source_matches) >= 1
    assert resolved_ip.source_matches[0]["source_id"] == "abuseipdb"

    # 2. Test WannaCry hash
    wannacry_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    extracted_hash = extractor.extract_from_text(f"File SHA256: {wannacry_hash}")[0]
    resolved_hash = resolver.resolve(extracted_hash, tenant_id="tenant-alpha", db=tiore_db_session)

    assert resolved_hash.classification == ThreatClassification.MALICIOUS
    assert resolved_hash.is_match is True
    assert "ransomware" in resolved_hash.threat_types
    assert resolved_hash.source_matches[0]["source_id"] == "virustotal"


def test_resolver_stale_record_evaluation(tiore_db_session):
    extractor = ObservableExtractor()
    resolver = IntelligenceResolver(cache=ObservableMemoryCache())
    repo = ThreatIntelRepository(tiore_db_session)

    source = repo.get_or_create_source("custom_feed", "Custom Stale Feed", "community", 3)
    extracted = extractor.extract_from_text("IOC domain legacy-malware-feed.com")[0]
    obs = repo.get_or_create_observable(extracted)

    # Insert an expired threat record (expired yesterday)
    yesterday = datetime.now(UTC) - timedelta(days=1)
    repo.save_record(
        observable_id=obs.id,
        source_id=source.id,
        classification="MALICIOUS",
        confidence=0.8,
        threat_types=["legacy_malware"],
        expires_at=yesterday,
    )

    resolved = resolver.resolve(extracted, tenant_id="tenant-alpha", db=tiore_db_session)
    assert resolved.classification == ThreatClassification.STALE
    assert resolved.is_match is False
    assert "expired/staled" in resolved.verdict_reason


def test_resolver_bulk_resolve(tiore_db_session):
    extractor = ObservableExtractor()
    resolver = IntelligenceResolver(cache=ObservableMemoryCache())
    seed_curated_threat_intel(tiore_db_session)

    text = "Traffic from 45.155.205.233 to 192.168.1.1 contacting threat-actor.xyz"
    extracted_list = extractor.extract_from_text(text)
    assert len(extracted_list) >= 3

    resolved_list = resolver.bulk_resolve(extracted_list, tenant_id="tenant-alpha", db=tiore_db_session)
    assert len(resolved_list) == len(extracted_list)

    classifications = {r.normalized_value: r.classification for r in resolved_list}
    assert classifications["45.155.205.233"] == ThreatClassification.MALICIOUS
    assert classifications["192.168.1.1"] == ThreatClassification.BENIGN
    assert classifications["threat-actor.xyz"] == ThreatClassification.MALICIOUS
