"""
LogSentry — TIORE Phase 4 Tests: Provider Adapters & Multi-Source Engine
========================================================================
Tests circuit breaking, rate limiting, provider eligibility, k-anonymity,
and database persistence with mocked network fixtures.
"""

from unittest.mock import MagicMock, patch
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.base import Base
from app.repositories.threat_intel_repository import ThreatIntelRepository
from app.tiore.extractor import ObservableExtractor
from app.tiore.models import (
    ExtractedObservable,
    ObservableType,
    PrivacyClassification,
    ThreatClassification,
    ValidationStatus,
)
from app.tiore.providers.abuseipdb import AbuseIPDBAdapter
from app.tiore.providers.alienvault import AlienVaultOTXAdapter
from app.tiore.providers.base import BaseObservableAdapter, CircuitState, ProviderLookupResult
from app.tiore.providers.hibp import HIBPPrefixAdapter
from app.tiore.providers.manager import ProviderManager
from app.tiore.providers.threatfox import ThreatFoxAdapter
from app.tiore.providers.urlhaus import URLhausAdapter
from app.tiore.providers.virustotal import VirusTotalAdapter


@pytest.fixture
def test_db_session():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


class DummyFailingAdapter(BaseObservableAdapter):
    def __init__(self):
        super().__init__(
            source_id="dummy_failing",
            name="Dummy Failing",
            supported_types=[ObservableType.IPV4],
            failure_threshold=3,
            recovery_timeout_sec=0.1,
        )

    def _execute_lookup(self, observable: ExtractedObservable) -> ProviderLookupResult:
        raise ConnectionResetError("Connection refused by remote host")


def test_base_adapter_circuit_breaker():
    adapter = DummyFailingAdapter()
    obs = ExtractedObservable(
        observable_type=ObservableType.IPV4,
        raw_value="198.51.100.1",
        normalized_value="198.51.100.1",
        masked_value="198.51.100.1",
        fingerprint="fp1",
        source_field="test",
        is_eligible_for_external_lookup=True,
    )

    assert adapter.get_circuit_state() == CircuitState.CLOSED

    # 3 failures should trigger circuit breaker OPEN
    for _ in range(3):
        res = adapter.lookup(obs)
        assert res.status == "error"

    assert adapter.get_circuit_state() == CircuitState.OPEN

    # Subsequent lookup should be blocked with circuit_open status
    res = adapter.lookup(obs)
    assert res.status == "circuit_open"
    assert "Circuit breaker OPEN" in res.error_message


def test_base_adapter_eligibility_privacy_check():
    adapter = AbuseIPDBAdapter()
    # RFC 1918 is ineligible for external lookup
    obs_internal = ExtractedObservable(
        observable_type=ObservableType.IPV4,
        raw_value="10.0.0.1",
        normalized_value="10.0.0.1",
        masked_value="10.0.0.1",
        fingerprint="fp_int",
        source_field="test",
        privacy_classification=PrivacyClassification.INTERNAL_RFC1918,
        is_eligible_for_external_lookup=False,
    )

    assert adapter.is_eligible(obs_internal) is False
    res = adapter.lookup(obs_internal)
    assert res.status == "skipped"


def test_abuseipdb_adapter_lookup():
    adapter = AbuseIPDBAdapter(api_key="test-api-key")
    obs = ExtractedObservable(
        observable_type=ObservableType.IPV4,
        raw_value="45.155.205.233",
        normalized_value="45.155.205.233",
        masked_value="45.155.205.233",
        fingerprint="fp_abuse",
        source_field="test",
        is_eligible_for_external_lookup=True,
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "ipAddress": "45.155.205.233",
            "abuseConfidenceScore": 100,
            "totalReports": 500,
            "countryCode": "NL",
            "isp": "Hostkey",
        }
    }

    with patch("httpx.Client.get", return_value=mock_resp):
        res = adapter.lookup(obs)

    assert res.status == "success"
    assert res.classification == ThreatClassification.MALICIOUS
    assert res.confidence == 1.0
    assert "abuse_ip" in res.threat_types
    assert res.evidence["abuse_score"] == 100


def test_urlhaus_adapter_lookup():
    adapter = URLhausAdapter()
    obs = ExtractedObservable(
        observable_type=ObservableType.URL,
        raw_value="http://malicious.example.com/payload.exe",
        normalized_value="http://malicious.example.com/payload.exe",
        masked_value="http://malicious.example.com/payload.exe",
        fingerprint="fp_urlhaus",
        source_field="test",
        is_eligible_for_external_lookup=True,
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "query_status": "ok",
        "url_status": "online",
        "threat": "malware_download",
        "reporter": "admin",
        "tags": ["cobalt_strike"],
    }

    with patch("httpx.Client.post", return_value=mock_resp):
        res = adapter.lookup(obs)

    assert res.status == "success"
    assert res.classification == ThreatClassification.MALICIOUS
    assert res.confidence == 0.98
    assert "malware_download" in res.threat_types


def test_threatfox_adapter_lookup():
    adapter = ThreatFoxAdapter()
    obs = ExtractedObservable(
        observable_type=ObservableType.DOMAIN,
        raw_value="c2.evil.com",
        normalized_value="c2.evil.com",
        masked_value="c2.evil.com",
        fingerprint="fp_fox",
        source_field="test",
        is_eligible_for_external_lookup=True,
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "query_status": "ok",
        "data": [
            {
                "ioc_value": "c2.evil.com",
                "threat_type": "botnet_cc",
                "malware_printable": "RedLine Stealer",
                "confidence_level": 95,
            }
        ],
    }

    with patch("httpx.Client.post", return_value=mock_resp):
        res = adapter.lookup(obs)

    assert res.status == "success"
    assert res.classification == ThreatClassification.MALICIOUS
    assert res.confidence == 0.95
    assert "redline stealer" in res.threat_types


def test_virustotal_adapter_lookup():
    adapter = VirusTotalAdapter(api_key="vt-test-key")
    sha256_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    obs = ExtractedObservable(
        observable_type=ObservableType.SHA256,
        raw_value=sha256_hash,
        normalized_value=sha256_hash,
        masked_value=sha256_hash,
        fingerprint="fp_vt",
        source_field="test",
        is_eligible_for_external_lookup=True,
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 65,
                    "suspicious": 2,
                    "harmless": 0,
                    "undetected": 3,
                },
                "popular_threat_classification": {
                    "suggested_threat_label": "ransomware.wannacry",
                },
            }
        }
    }

    with patch("httpx.Client.get", return_value=mock_resp):
        res = adapter.lookup(obs)

    assert res.status == "success"
    assert res.classification == ThreatClassification.MALICIOUS
    assert "ransomware.wannacry" in res.threat_types
    assert res.evidence["malicious"] == 65


def test_hibp_k_anonymity_privacy_and_lookup():
    adapter = HIBPPrefixAdapter()
    email = "breached_user@example.com"
    extractor = ObservableExtractor()
    obs = extractor.validate_and_normalize_email(email)

    assert obs is not None
    assert adapter.is_eligible(obs) is True

    # Calculate SHA1 for breached_user@example.com
    import hashlib
    sha1_hex = hashlib.sha1(email.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hex[:5]
    suffix = sha1_hex[5:]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    # Simulate HIBP response containing our suffix with count 42
    mock_resp.text = f"00000000000000000000000000000000000:1\r\n{suffix}:42\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:3"

    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = mock_resp
        res = adapter.lookup(obs)

        # Verify that the URL requested ONLY has the 5-char prefix, never the email or full hash!
        called_url = mock_get.call_args[0][0]
        assert called_url == f"https://api.pwnedpasswords.com/range/{prefix}"
        assert email not in called_url
        assert sha1_hex not in called_url

    assert res.status == "success"
    assert res.classification == ThreatClassification.EXPOSED
    assert res.confidence == 0.95
    assert res.evidence["exposure_count"] == 42
    assert "data_breach" in res.threat_types


def test_provider_manager_and_persistence(test_db_session):
    repo = ThreatIntelRepository(test_db_session)
    repo.get_or_create_source("abuseipdb", "AbuseIPDB", "commercial", 1)

    manager = ProviderManager()
    extractor = ObservableExtractor()
    obs = extractor.extract_from_text("Alert on 45.155.205.233")[0]

    mock_res = ProviderLookupResult(
        source_id="abuseipdb",
        classification=ThreatClassification.MALICIOUS,
        confidence=0.95,
        threat_types=["scanner"],
        evidence={"score": 100},
        status="success",
    )

    with patch.object(AbuseIPDBAdapter, "lookup", return_value=mock_res):
        saved_ids = manager.persist_results(obs, [mock_res], db=test_db_session)

    assert len(saved_ids) == 1
    # Check that record is in database
    records = repo.get_records_for_observable(repo.get_observable_by_fingerprint(obs.fingerprint).id)
    assert len(records) == 1
    assert records[0].classification == "MALICIOUS"
    assert records[0].confidence == 0.95
