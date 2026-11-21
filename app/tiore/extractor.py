"""
LogSentry — TIORE Observable Extraction & Normalization Engine
==============================================================
Extracts, validates, normalizes, and classifies security observables
from structured and unstructured log payloads with strict privacy boundaries.
"""

import hashlib
import hmac
import ipaddress
import logging
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.tiore.models import (
    ExtractedObservable,
    ObservableType,
    PrivacyClassification,
    ValidationStatus,
)

logger = logging.getLogger(__name__)

# Sensitive query parameters stripped from URLs prior to reputation hashing
SENSITIVE_URL_PARAMS = {
    "token",
    "access_token",
    "id_token",
    "refresh_token",
    "auth",
    "authorization",
    "bearer",
    "key",
    "api_key",
    "apikey",
    "secret",
    "client_secret",
    "password",
    "pass",
    "pwd",
    "session",
    "session_id",
    "sess",
    "sig",
    "signature",
    "code",
    "state",
    "jwt",
    "cookie",
    "credential",
    "user",
    "username",
    "email",
    "phone",
    "account",
    "pin",
    "private",
    "ssn",
}

# Internal TLDs and suffix reservations
INTERNAL_TLDS = {
    "local",
    "internal",
    "lan",
    "corp",
    "home",
    "home.arpa",
    "test",
    "localhost",
    "invalid",
    "example",
}

# Regex patterns for fast extraction
IPV4_REGEX = re.compile(
    r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b"
)
IPV6_REGEX = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|"
    r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:|"
    r"\b:(?::[0-9a-fA-F]{1,4}){1,7}\b|"
    r"\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b"
)
URL_REGEX = re.compile(r"https?://[^\s<>\"'{}|\\^`\[\]]+")
DOMAIN_REGEX = re.compile(
    r"\b(?=.{4,253}\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b"
)
HASH_SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")
HASH_SHA1_REGEX = re.compile(r"\b[a-fA-F0-9]{40}\b")
HASH_MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")
EMAIL_REGEX = re.compile(r"\b[a-zA-Z0-9_.+-]+@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b")
PHONE_E164_REGEX = re.compile(
    r"(?:\+)[1-9]\d{0,2}[-.\s]?(?:\(?\d{1,4}\)?[-.\s]?)?\d{1,4}[-.\s]?\d{1,9}\b"
)


class ObservableExtractor:
    """
    Production-grade observable extraction and normalization engine.
    Ensures safe parsing, input size bounds, deduplication, and zero-leakage privacy filters.
    """

    def __init__(self, hmac_key: str | bytes | None = None) -> None:
        if hmac_key:
            self._hmac_key = (
                hmac_key if isinstance(hmac_key, bytes) else hmac_key.encode("utf-8")
            )
        else:
            from app.core.crypto import get_pii_hmac_key

            self._hmac_key = get_pii_hmac_key()

    def _generate_fingerprint(
        self, obs_type: ObservableType, normalized_value: str
    ) -> str:
        """
        Generates deterministic fingerprint.
        Public indicators use standard SHA-256.
        PII (email, phone) uses keyed HMAC-SHA256 to prevent dictionary/rainbow table recovery.
        """
        if obs_type in (ObservableType.EMAIL, ObservableType.PHONE):
            return hmac.new(
                self._hmac_key,
                f"{obs_type.value}:{normalized_value}".encode(),
                hashlib.sha256,
            ).hexdigest()
        return hashlib.sha256(
            f"{obs_type.value}:{normalized_value}".encode()
        ).hexdigest()

    def _mask_value(self, obs_type: ObservableType, val: str) -> str:
        """Masks sensitive values for analyst display."""
        if obs_type == ObservableType.EMAIL:
            parts = val.split("@", 1)
            if len(parts) == 2:
                user, domain = parts
                if len(user) <= 2:
                    masked_user = user[0] + "***"
                else:
                    masked_user = user[0] + "***" + user[-1]
                return f"{masked_user}@{domain}"
            return "***@***"
        if obs_type == ObservableType.PHONE:
            cleaned = re.sub(r"[^\d+]", "", val)
            if len(cleaned) >= 7:
                return f"{cleaned[:3]}***-***{cleaned[-4:]}"
            return "+***"
        if obs_type == ObservableType.URL:
            # Mask credentials if embedded in URL userinfo
            parsed = urlsplit(val)
            if parsed.username or parsed.password:
                netloc = parsed.netloc.split("@")[-1]
                return urlunsplit(
                    (
                        parsed.scheme,
                        f"***:***@{netloc}",
                        parsed.path,
                        parsed.query,
                        parsed.fragment,
                    )
                )
        return val

    # -------------------------------------------------------------------------
    # Individual Type Parsers & Validators
    # -------------------------------------------------------------------------

    def validate_and_normalize_ip(
        self, raw_ip: str, source_field: str = "generic"
    ) -> ExtractedObservable | None:
        clean = raw_ip.strip()
        try:
            ip_obj = ipaddress.ip_address(clean)
        except ValueError:
            return None

        is_v4 = isinstance(ip_obj, ipaddress.IPv4Address)
        obs_type = ObservableType.IPV4 if is_v4 else ObservableType.IPV6
        normalized = str(ip_obj.compressed if not is_v4 else ip_obj)

        # Privacy Classification
        if ip_obj.is_loopback:
            privacy = PrivacyClassification.LOOPBACK
            eligible = False
        elif ip_obj.is_link_local or normalized == "169.254.169.254":
            privacy = PrivacyClassification.LINK_LOCAL_METADATA
            eligible = False
        elif ip_obj.is_private or ip_obj.is_reserved:
            privacy = PrivacyClassification.INTERNAL_RFC1918
            eligible = False
        elif ip_obj.is_multicast:
            privacy = PrivacyClassification.INTERNAL_RFC1918
            eligible = False
        else:
            privacy = PrivacyClassification.PUBLIC_ROUTABLE
            eligible = True

        return ExtractedObservable(
            observable_type=obs_type,
            raw_value=raw_ip,
            normalized_value=normalized,
            masked_value=normalized,
            fingerprint=self._generate_fingerprint(obs_type, normalized),
            source_field=source_field,
            validation_status=ValidationStatus.VALID,
            privacy_classification=privacy,
            is_eligible_for_external_lookup=eligible,
            metadata={
                "version": 4 if is_v4 else 6,
                "is_private": ip_obj.is_private,
                "is_loopback": ip_obj.is_loopback,
            },
        )

    def validate_and_normalize_domain(
        self, raw_domain: str, source_field: str = "generic"
    ) -> ExtractedObservable | None:
        clean = raw_domain.strip().rstrip(".").lower()
        if not clean or len(clean) > 253 or " " in clean:
            return None

        # Verify not an IP address passed as domain
        try:
            ipaddress.ip_address(clean)
            return None
        except ValueError:
            pass

        # Handle IDN punycode if needed
        try:
            ascii_domain = clean.encode("idna").decode("ascii")
        except Exception:
            ascii_domain = clean

        if clean == "localhost":
            return ExtractedObservable(
                observable_type=ObservableType.DOMAIN,
                raw_value=raw_domain,
                normalized_value="localhost",
                masked_value="localhost",
                fingerprint=self._generate_fingerprint(
                    ObservableType.DOMAIN, "localhost"
                ),
                source_field=source_field,
                validation_status=ValidationStatus.VALID,
                privacy_classification=PrivacyClassification.INTERNAL_DOMAIN,
                is_eligible_for_external_lookup=False,
                metadata={"tld": "localhost", "subdomains": [], "is_internal": True},
            )

        if not DOMAIN_REGEX.match(ascii_domain):
            return None

        parts = ascii_domain.split(".")
        tld = parts[-1]
        is_internal = tld in INTERNAL_TLDS or any(
            part in ("localhost", "internal", "lan", "corp", "corpnet")
            for part in parts
        )

        privacy = (
            PrivacyClassification.INTERNAL_DOMAIN
            if is_internal
            else PrivacyClassification.PUBLIC_ROUTABLE
        )

        return ExtractedObservable(
            observable_type=ObservableType.DOMAIN,
            raw_value=raw_domain,
            normalized_value=clean,
            masked_value=clean,
            fingerprint=self._generate_fingerprint(ObservableType.DOMAIN, clean),
            source_field=source_field,
            validation_status=ValidationStatus.VALID,
            privacy_classification=privacy,
            is_eligible_for_external_lookup=not is_internal,
            metadata={
                "tld": tld,
                "subdomains": parts[:-2] if len(parts) > 2 else [],
                "is_internal": is_internal,
            },
        )

    def validate_and_normalize_url(
        self, raw_url: str, source_field: str = "generic"
    ) -> ExtractedObservable | None:
        clean = raw_url.strip()
        if len(clean) > 2048:
            return None

        try:
            parsed = urlsplit(clean)
        except Exception:
            return None

        if parsed.scheme.lower() not in ("http", "https"):
            return None

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return None

        # Check if hostname is an internal IP or internal domain
        is_internal = False
        privacy = PrivacyClassification.PUBLIC_ROUTABLE
        try:
            ip_obj = ipaddress.ip_address(hostname)
            if ip_obj.is_link_local or str(ip_obj) == "169.254.169.254":
                privacy = PrivacyClassification.LINK_LOCAL_METADATA
                is_internal = True
            elif ip_obj.is_loopback:
                privacy = PrivacyClassification.LOOPBACK
                is_internal = True
            elif ip_obj.is_private:
                privacy = PrivacyClassification.INTERNAL_RFC1918
                is_internal = True
        except ValueError:
            tld = hostname.split(".")[-1]
            if tld in INTERNAL_TLDS or hostname in ("localhost", "internal"):
                privacy = PrivacyClassification.INTERNAL_DOMAIN
                is_internal = True

        # Sanitize query parameters (strip sensitive tokens with strict disclosure policy)
        sanitized_query = ""
        if parsed.query:
            filtered_params = []
            for k, v in parse_qsl(parsed.query, keep_blank_values=True):
                k_lower = k.lower()
                is_sensitive = k_lower in SENSITIVE_URL_PARAMS or any(
                    s in k_lower
                    for s in ("token", "secret", "pass", "auth", "key", "cred")
                )
                if is_sensitive:
                    filtered_params.append((k, "REDACTED"))
                else:
                    filtered_params.append((k, v))
            sanitized_query = urlencode(filtered_params)

        # Standardize port removal
        netloc = hostname
        port = parsed.port
        if port and not (
            (parsed.scheme == "http" and port == 80)
            or (parsed.scheme == "https" and port == 443)
        ):
            netloc = f"{hostname}:{port}"

        normalized_url = urlunsplit(
            (
                parsed.scheme.lower(),
                netloc,
                parsed.path or "/",
                sanitized_query,
                "",  # Strip fragment
            )
        )

        return ExtractedObservable(
            observable_type=ObservableType.URL,
            raw_value=raw_url,
            normalized_value=normalized_url,
            masked_value=self._mask_value(ObservableType.URL, normalized_url),
            fingerprint=self._generate_fingerprint(ObservableType.URL, normalized_url),
            source_field=source_field,
            validation_status=ValidationStatus.VALID,
            privacy_classification=privacy,
            is_eligible_for_external_lookup=not is_internal,
            metadata={
                "scheme": parsed.scheme.lower(),
                "hostname": hostname,
                "path": parsed.path,
                "is_internal": is_internal,
            },
        )

    def validate_and_normalize_hash(
        self, raw_hash: str, source_field: str = "generic"
    ) -> ExtractedObservable | None:
        clean = raw_hash.strip().lower()
        length = len(clean)

        if length == 32 and HASH_MD5_REGEX.fullmatch(clean):
            obs_type = ObservableType.MD5
        elif length == 40 and HASH_SHA1_REGEX.fullmatch(clean):
            obs_type = ObservableType.SHA1
        elif length == 64 and HASH_SHA256_REGEX.fullmatch(clean):
            obs_type = ObservableType.SHA256
        else:
            return None

        return ExtractedObservable(
            observable_type=obs_type,
            raw_value=raw_hash,
            normalized_value=clean,
            masked_value=clean,
            fingerprint=self._generate_fingerprint(obs_type, clean),
            source_field=source_field,
            validation_status=ValidationStatus.VALID,
            privacy_classification=PrivacyClassification.PUBLIC_ROUTABLE,
            is_eligible_for_external_lookup=True,
            metadata={"algorithm": obs_type.value, "length": length},
        )

    def validate_and_normalize_email(
        self, raw_email: str, source_field: str = "generic"
    ) -> ExtractedObservable | None:
        clean = raw_email.strip().lower()
        if not clean or len(clean) > 254:
            return None

        if not EMAIL_REGEX.fullmatch(clean):
            return None

        domain = clean.split("@")[-1]
        tld = domain.split(".")[-1]
        is_internal = tld in INTERNAL_TLDS

        return ExtractedObservable(
            observable_type=ObservableType.EMAIL,
            raw_value=raw_email,
            normalized_value=clean,
            masked_value=self._mask_value(ObservableType.EMAIL, clean),
            fingerprint=self._generate_fingerprint(ObservableType.EMAIL, clean),
            source_field=source_field,
            validation_status=ValidationStatus.VALID,
            privacy_classification=PrivacyClassification.PII_SENSITIVE,
            is_eligible_for_external_lookup=False,  # Zero-disclosure default for PII
            metadata={
                "domain": domain,
                "is_internal": is_internal,
            },
        )

    def validate_and_normalize_phone(
        self, raw_phone: str, source_field: str = "generic"
    ) -> ExtractedObservable | None:
        clean = raw_phone.strip()
        # Require international prefix '+' to avoid ambiguous guessing of local area codes
        if not clean.startswith("+"):
            return None

        digits_only = re.sub(r"[^\d]", "", clean)
        # E.164 limits numbers to maximum 15 digits (excluding '+') and minimum 7
        if len(digits_only) < 7 or len(digits_only) > 15:
            return None

        normalized = f"+{digits_only}"

        return ExtractedObservable(
            observable_type=ObservableType.PHONE,
            raw_value=raw_phone,
            normalized_value=normalized,
            masked_value=self._mask_value(ObservableType.PHONE, normalized),
            fingerprint=self._generate_fingerprint(ObservableType.PHONE, normalized),
            source_field=source_field,
            validation_status=ValidationStatus.VALID,
            privacy_classification=PrivacyClassification.PII_SENSITIVE,
            is_eligible_for_external_lookup=False,  # Zero-disclosure default for PII
            metadata={"digits": len(digits_only)},
        )

    # -------------------------------------------------------------------------
    # Comprehensive Event & Unstructured Text Extraction
    # -------------------------------------------------------------------------

    def extract_from_text(
        self, text: str, source_field: str = "raw_log"
    ) -> list[ExtractedObservable]:
        """
        Extracts all recognized observables from arbitrary text with deduplication.
        Safely enforces maximum text scan size (64 KB) to prevent regex DoS.
        """
        if not text:
            return []

        # Bound input text size for safety
        bounded_text = text[:65536]
        results: list[ExtractedObservable] = []
        seen_fingerprints: set[str] = set()

        def add_if_unique(obs: ExtractedObservable | None):
            if obs and obs.fingerprint not in seen_fingerprints:
                seen_fingerprints.add(obs.fingerprint)
                results.append(obs)

        # 1. URLs (extract URLs first so domain/ip extractor doesn't duplicate hostnames from URLs)
        extracted_url_hosts: set[str] = set()
        for match in URL_REGEX.finditer(bounded_text):
            obs = self.validate_and_normalize_url(
                match.group(0), source_field=source_field
            )
            if obs:
                add_if_unique(obs)
                host = obs.metadata.get("hostname")
                if host:
                    extracted_url_hosts.add(host)

        # 2. Email addresses
        for match in EMAIL_REGEX.finditer(bounded_text):
            add_if_unique(
                self.validate_and_normalize_email(
                    match.group(0), source_field=source_field
                )
            )

        # 3. Phone numbers with + prefix
        for match in PHONE_E164_REGEX.finditer(bounded_text):
            add_if_unique(
                self.validate_and_normalize_phone(
                    match.group(0), source_field=source_field
                )
            )

        # 4. IP Addresses (IPv4 & IPv6)
        for match in IPV4_REGEX.finditer(bounded_text):
            add_if_unique(
                self.validate_and_normalize_ip(
                    match.group(0), source_field=source_field
                )
            )
        for match in IPV6_REGEX.finditer(bounded_text):
            add_if_unique(
                self.validate_and_normalize_ip(
                    match.group(0), source_field=source_field
                )
            )

        # 5. File Hashes
        for match in HASH_SHA256_REGEX.finditer(bounded_text):
            add_if_unique(
                self.validate_and_normalize_hash(
                    match.group(0), source_field=source_field
                )
            )
        for match in HASH_SHA1_REGEX.finditer(bounded_text):
            add_if_unique(
                self.validate_and_normalize_hash(
                    match.group(0), source_field=source_field
                )
            )
        for match in HASH_MD5_REGEX.finditer(bounded_text):
            add_if_unique(
                self.validate_and_normalize_hash(
                    match.group(0), source_field=source_field
                )
            )

        # 6. Domains (skip if already extracted as part of a URL)
        for match in DOMAIN_REGEX.finditer(bounded_text):
            dom_candidate = match.group(0)
            if dom_candidate.lower() not in extracted_url_hosts:
                add_if_unique(
                    self.validate_and_normalize_domain(
                        dom_candidate, source_field=source_field
                    )
                )

        return results

    def extract_from_event(
        self, event_data: dict[str, Any]
    ) -> list[ExtractedObservable]:
        """
        Deep extraction across structured event fields (source_ip, destination_ip,
        endpoint, path, command_line, raw_log, and parsed_data).
        """
        results: list[ExtractedObservable] = []
        seen_fingerprints: set[str] = set()

        def add_unique(items: list[ExtractedObservable]):
            for item in items:
                if item.fingerprint not in seen_fingerprints:
                    seen_fingerprints.add(item.fingerprint)
                    results.append(item)

        # Direct structured field extraction
        if event_data.get("source_ip"):
            obs = self.validate_and_normalize_ip(
                str(event_data["source_ip"]), source_field="source_ip"
            )
            if obs:
                add_unique([obs])

        if event_data.get("destination_ip"):
            obs = self.validate_and_normalize_ip(
                str(event_data["destination_ip"]), source_field="destination_ip"
            )
            if obs:
                add_unique([obs])

        # Parse string fields
        text_fields = ["endpoint", "path", "command_line", "user", "raw_log"]
        for field in text_fields:
            val = event_data.get(field)
            if isinstance(val, str) and val.strip():
                add_unique(self.extract_from_text(val, source_field=field))

        # Recursively scan parsed_data dictionary
        parsed_data = event_data.get("parsed_data")
        if isinstance(parsed_data, dict):
            for k, v in parsed_data.items():
                if isinstance(v, str) and v.strip():
                    add_unique(
                        self.extract_from_text(v, source_field=f"parsed_data.{k}")
                    )

        return results
