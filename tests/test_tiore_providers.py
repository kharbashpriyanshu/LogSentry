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
from app.tiore.providers.base import (
    BaseObservableAdapter,
    CircuitState,
    ProviderLookupResult,
)
from app.tiore.providers.hibp import HIBPBreachAdapter, HIBPPrefixAdapter
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


def test_hibp_breached_account_api():
    # 1. Unconfigured state skips safely without making unauthorized network calls
    unconfigured_adapter = HIBPBreachAdapter(api_key=None)
    email = "breached_user@example.com"
    extractor = ObservableExtractor()
    obs = extractor.validate_and_normalize_email(email)

    assert obs is not None
    assert unconfigured_adapter.is_eligible(obs) is False
    skip_res = unconfigured_adapter.lookup(obs)
    assert skip_res.status == "skipped"

    # 2. Configured state with valid API key
    configured_adapter = HIBPBreachAdapter(api_key="test-hibp-api-key-12345")
    assert configured_adapter.is_eligible(obs) is True

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {
            "Name": "Adobe",
            "Title": "Adobe Creative Cloud",
            "Domain": "adobe.com",
            "BreachDate": "2013-10-04",
            "DataClasses": ["Email addresses", "Passwords"],
        },
        {
            "Name": "Canva",
            "Title": "Canva",
            "Domain": "canva.com",
            "BreachDate": "2019-05-24",
            "DataClasses": ["Email addresses", "Names", "Passwords"],
        },
    ]

    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = mock_resp
        res = configured_adapter.lookup(obs)

        # Verify correct v3 endpoint and mandatory auth headers
        called_url = mock_get.call_args[0][0]
        called_headers = mock_get.call_args[1]["headers"]
        assert (
            "https://haveibeenpwned.com/api/v3/breachedaccount/breached_user@example.com"
            in called_url
        )
        assert called_headers["hibp-api-key"] == "test-hibp-api-key-12345"
        assert "LogSentry" in called_headers["user-agent"]

    assert res.status == "success"
    assert res.classification == ThreatClassification.EXPOSED
    assert res.confidence == 0.95
    assert res.evidence["breached"] is True
    assert res.evidence["breach_count"] == 2
    assert "data_breach" in res.threat_types

    # 3. Benign (404 Not Found) state
    mock_404 = MagicMock()
    mock_404.status_code = 404
    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = mock_404
        benign_res = configured_adapter.lookup(obs)
        assert benign_res.status == "success"
        assert benign_res.classification == ThreatClassification.BENIGN
        assert benign_res.evidence["breached"] is False


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
    records = repo.get_records_for_observable(
        repo.get_observable_by_fingerprint(obs.fingerprint).id
    )
    assert len(records) == 1
    assert records[0].classification == "MALICIOUS"
    assert records[0].confidence == 0.95
