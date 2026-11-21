"""
LogSentry — TIORE Observable Extractor Unit & Adversarial Tests
==============================================================
Verifies extraction, normalization, privacy-preservation, masking,
fingerprinting, and adversarial boundary enforcement across all 6 observable types.
"""

import pytest

from app.tiore.extractor import ObservableExtractor
from app.tiore.models import ObservableType, PrivacyClassification, ValidationStatus


@pytest.fixture
def extractor():
    return ObservableExtractor(hmac_key="test-tiore-master-secret-key-2026")


# ==============================================================================
# 1. IP Address Validation & Privacy Bounds
# ==============================================================================

def test_extract_public_ipv4(extractor):
    obs = extractor.validate_and_normalize_ip("185.220.101.5", source_field="source_ip")
    assert obs is not None
    assert obs.observable_type == ObservableType.IPV4
    assert obs.normalized_value == "185.220.101.5"
    assert obs.privacy_classification == PrivacyClassification.PUBLIC_ROUTABLE
    assert obs.is_eligible_for_external_lookup is True
    assert obs.validation_status == ValidationStatus.VALID


def test_extract_private_rfc1918_ipv4(extractor):
    for ip in ["192.168.1.1", "10.0.0.1", "172.16.50.4"]:
        obs = extractor.validate_and_normalize_ip(ip, source_field="source_ip")
        assert obs is not None
        assert obs.privacy_classification == PrivacyClassification.INTERNAL_RFC1918
        # STRICT PRIVACY: Private IPs must NEVER be eligible for external lookup
        assert obs.is_eligible_for_external_lookup is False


def test_extract_loopback_and_metadata_ip(extractor):
    # Loopback
    obs_loop = extractor.validate_and_normalize_ip("127.0.0.1")
    assert obs_loop is not None
    assert obs_loop.privacy_classification == PrivacyClassification.LOOPBACK
    assert obs_loop.is_eligible_for_external_lookup is False

    # Cloud metadata endpoint
    obs_meta = extractor.validate_and_normalize_ip("169.254.169.254")
    assert obs_meta is not None
    assert obs_meta.privacy_classification == PrivacyClassification.LINK_LOCAL_METADATA
    assert obs_meta.is_eligible_for_external_lookup is False


def test_extract_ipv6(extractor):
    # Public IPv6
    obs_v6 = extractor.validate_and_normalize_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    assert obs_v6 is not None
    assert obs_v6.observable_type == ObservableType.IPV6
    # Compressed form
    assert obs_v6.normalized_value == "2001:db8:85a3::8a2e:370:7334"

    # Loopback IPv6
    obs_v6_loop = extractor.validate_and_normalize_ip("::1")
    assert obs_v6_loop is not None
    assert obs_v6_loop.privacy_classification == PrivacyClassification.LOOPBACK
    assert obs_v6_loop.is_eligible_for_external_lookup is False


def test_invalid_ips_rejected(extractor):
    for bad_ip in ["999.999.999.999", "192.168.1.300", "not-an-ip", "1.2.3"]:
        assert extractor.validate_and_normalize_ip(bad_ip) is None


# ==============================================================================
# 2. Domain Normalization & Internal Scoping
# ==============================================================================

def test_extract_public_domain(extractor):
    obs = extractor.validate_and_normalize_domain("EVIL-C2.NET.")
    assert obs is not None
    assert obs.observable_type == ObservableType.DOMAIN
    # Lowercase and trailing dot removed
    assert obs.normalized_value == "evil-c2.net"
    assert obs.privacy_classification == PrivacyClassification.PUBLIC_ROUTABLE
    assert obs.is_eligible_for_external_lookup is True
    assert obs.metadata["tld"] == "net"


def test_extract_internal_domain(extractor):
    for dom in ["dc01.corp", "bastion.internal", "server.local", "router.lan", "localhost"]:
        obs = extractor.validate_and_normalize_domain(dom)
        assert obs is not None
        assert obs.privacy_classification == PrivacyClassification.INTERNAL_DOMAIN
        # Internal domains must not be queried against public threat feeds
        assert obs.is_eligible_for_external_lookup is False


def test_domain_rejects_ip_or_invalid(extractor):
    assert extractor.validate_and_normalize_domain("192.168.1.1") is None
    assert extractor.validate_and_normalize_domain("invalid domain with spaces") is None
    assert extractor.validate_and_normalize_domain("a" * 260 + ".com") is None


# ==============================================================================
# 3. URL Normalization & Parameter Sanitization
# ==============================================================================

def test_extract_url_with_sensitive_param_stripping(extractor):
    raw = "https://evil-c2.net:443/beacon/gate.php?token=SECRET_SESSION_TOKEN_123&client=win10&api_key=XYZ987"
    obs = extractor.validate_and_normalize_url(raw)
    assert obs is not None
    assert obs.observable_type == ObservableType.URL
    # Default port 443 stripped, sensitive token/api_key REDACTED, client retained
    assert "SECRET_SESSION_TOKEN_123" not in obs.normalized_value
    assert "XYZ987" not in obs.normalized_value
    assert "token=REDACTED" in obs.normalized_value
    assert "api_key=REDACTED" in obs.normalized_value
    assert "client=win10" in obs.normalized_value
    assert obs.is_eligible_for_external_lookup is True


def test_internal_url_ineligible_for_external_lookup(extractor):
    internal_urls = [
        "http://192.168.1.50/admin/panel",
        "https://auth.internal/oauth2/token",
        "http://127.0.0.1:8000/api/v1/metrics",
    ]
    for url in internal_urls:
        obs = extractor.validate_and_normalize_url(url)
        assert obs is not None
        assert obs.privacy_classification == PrivacyClassification.INTERNAL_DOMAIN
        assert obs.is_eligible_for_external_lookup is False


# ==============================================================================
# 4. Hash Extraction (MD5, SHA-1, SHA-256)
# ==============================================================================

def test_extract_hashes(extractor):
    md5 = "e4d909c290d0fb1ca068ffaddf22cbd0"
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    obs_md5 = extractor.validate_and_normalize_hash(md5.upper())
    assert obs_md5 is not None
    assert obs_md5.observable_type == ObservableType.MD5
    assert obs_md5.normalized_value == md5.lower()
    assert obs_md5.is_eligible_for_external_lookup is True

    obs_sha1 = extractor.validate_and_normalize_hash(sha1)
    assert obs_sha1 is not None
    assert obs_sha1.observable_type == ObservableType.SHA1
    assert obs_sha1.normalized_value == sha1

    obs_sha256 = extractor.validate_and_normalize_hash(sha256)
    assert obs_sha256 is not None
    assert obs_sha256.observable_type == ObservableType.SHA256
    assert obs_sha256.normalized_value == sha256


def test_invalid_hash_rejected(extractor):
    # Wrong character length or invalid hex characters
    assert extractor.validate_and_normalize_hash("e4d909c290d0fb1ca068ffaddf22cbd") is None  # 31 chars
    assert extractor.validate_and_normalize_hash("e4d909c290d0fb1ca068ffaddf22cbz0") is None  # 'z' invalid hex


# ==============================================================================
# 5. Email & Phone PII Protection (Keyed HMAC & Zero External Disclosure)
# ==============================================================================

def test_extract_email_pii_shielding(extractor):
    email = "SecOps-Analyst@Corp-Security.org"
    obs = extractor.validate_and_normalize_email(email)
    assert obs is not None
    assert obs.observable_type == ObservableType.EMAIL
    assert obs.normalized_value == "secops-analyst@corp-security.org"
    # Masked representation for analyst view
    assert obs.masked_value == "s***t@corp-security.org"
    # Zero external disclosure default
    assert obs.privacy_classification == PrivacyClassification.PII_SENSITIVE
    assert obs.is_eligible_for_external_lookup is False

    # Keyed HMAC fingerprint differs from simple SHA-256
    import hashlib
    raw_sha256 = hashlib.sha256(f"email:{obs.normalized_value}".encode("utf-8")).hexdigest()
    assert obs.fingerprint != raw_sha256  # Protected against rainbow table attacks


def test_extract_phone_pii_shielding(extractor):
    phone = "+1 (800) 555-0199"
    obs = extractor.validate_and_normalize_phone(phone)
    assert obs is not None
    assert obs.observable_type == ObservableType.PHONE
    assert obs.normalized_value == "+18005550199"
    assert obs.masked_value == "+18***-***0199"
    assert obs.privacy_classification == PrivacyClassification.PII_SENSITIVE
    assert obs.is_eligible_for_external_lookup is False

    # Incomplete phone number rejected
    assert extractor.validate_and_normalize_phone("+1234") is None
    # Ambiguous phone without '+' international prefix rejected
    assert extractor.validate_and_normalize_phone("555-0199") is None


# ==============================================================================
# 6. Deep Event & Text Extraction with Deduplication
# ==============================================================================

def test_extract_from_text_mixed_payload(extractor):
    raw_log = (
        'Nov 21 12:00:01 bastion sshd[123]: Failed login from 198.51.100.42 '
        'user bad-actor@evil-phish.com downloading http://c2.evil-corp.com/payload.exe '
        'with hash e4d909c290d0fb1ca068ffaddf22cbd0 from +1-555-019-2831'
    )
    observables = extractor.extract_from_text(raw_log)
    types = {o.observable_type for o in observables}

    assert ObservableType.IPV4 in types
    assert ObservableType.EMAIL in types
    assert ObservableType.URL in types
    assert ObservableType.MD5 in types
    assert ObservableType.PHONE in types

    # Verify deduplication
    duplicate_log = f"{raw_log} repeated {raw_log}"
    deduped = extractor.extract_from_text(duplicate_log)
    assert len(deduped) == len(observables)


def test_extract_from_structured_event(extractor):
    event = {
        "source_ip": "185.220.101.5",
        "destination_ip": "10.0.0.15",
        "endpoint": "/api/v1/auth/login?redirect=https://phish.net/login",
        "command_line": "powershell -enc aW52b2tl (hash ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad)",
        "parsed_data": {
            "referrer": "https://malicious-referrer.org/attack",
            "contact": "attacker@darkweb-forum.net",
        },
    }
    extracted = extractor.extract_from_event(event)
    assert len(extracted) >= 5

    source_fields = {o.source_field for o in extracted}
    assert "source_ip" in source_fields
    assert "destination_ip" in source_fields
    assert "endpoint" in source_fields
    assert "command_line" in source_fields
    assert "parsed_data.contact" in source_fields


def test_adversarial_oversized_payload_handling(extractor):
    # 1 MB random payload must be safely truncated and processed without hang
    huge_text = ("A" * 1000 + " 185.220.101.5 ") * 500
    extracted = extractor.extract_from_text(huge_text)
    assert len(extracted) == 1
    assert extracted[0].normalized_value == "185.220.101.5"
