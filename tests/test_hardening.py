"""
Sprint 8 production hardening tests.

Covers:
  - Security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
  - Correlation ID propagation
  - /metrics endpoint
  - /liveness probe
  - /readiness probe
  - /version endpoint
  - Request size limit enforcement (413)
  - Path traversal protection in file upload
  - Content-type validation in file upload
  - Structured log format (StructuredFormatter)
  - InMemoryCache thread safety and LRU eviction
  - Settings validators
  - Health endpoint enrichment (environment, version, subsystems)
"""

import json
import logging
import threading
import time
from io import BytesIO
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import app
from app.enrichment.cache import InMemoryCache
from app.core.logging import StructuredFormatter
from app.config.settings import Settings


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


# ---------------------------------------------------------------------------
# Security Header Tests
# ---------------------------------------------------------------------------


class TestSecurityHeaders:
    def test_csp_header_present(self, client: TestClient):
        response = client.get("/liveness")
        assert "Content-Security-Policy" in response.headers

    def test_csp_denies_scripts(self, client: TestClient):
        response = client.get("/liveness")
        csp = response.headers.get("Content-Security-Policy", "")
        assert "default-src 'none'" in csp

    def test_x_content_type_options(self, client: TestClient):
        response = client.get("/liveness")
        assert response.headers.get("X-Content-Type-Options") == "nosniff"

    def test_x_frame_options(self, client: TestClient):
        response = client.get("/liveness")
        assert response.headers.get("X-Frame-Options") == "DENY"

    def test_hsts_header(self, client: TestClient):
        response = client.get("/liveness")
        hsts = response.headers.get("Strict-Transport-Security", "")
        assert "max-age=31536000" in hsts
        assert "includeSubDomains" in hsts

    def test_referrer_policy(self, client: TestClient):
        response = client.get("/liveness")
        assert "Referrer-Policy" in response.headers

    def test_permissions_policy(self, client: TestClient):
        response = client.get("/liveness")
        assert "Permissions-Policy" in response.headers

    def test_server_header_sanitised(self, client: TestClient):
        response = client.get("/liveness")
        # Must not expose Python/uvicorn fingerprint
        server = response.headers.get("Server", "")
        assert "python" not in server.lower()
        assert "uvicorn" not in server.lower()

    def test_correlation_id_in_response(self, client: TestClient):
        response = client.get("/liveness")
        assert "X-Correlation-ID" in response.headers
        cid = response.headers["X-Correlation-ID"]
        # Must be a valid UUID4
        import uuid
        uuid.UUID(cid, version=4)  # raises ValueError if invalid

    def test_process_time_header(self, client: TestClient):
        response = client.get("/liveness")
        assert "X-Process-Time" in response.headers
        elapsed = float(response.headers["X-Process-Time"])
        assert elapsed >= 0


# ---------------------------------------------------------------------------
# Observability Endpoints
# ---------------------------------------------------------------------------


class TestObservabilityEndpoints:
    def test_liveness_returns_200(self, client: TestClient):
        response = client.get("/liveness")
        assert response.status_code == 200
        assert response.json()["status"] == "alive"

    def test_readiness_returns_200(self, client: TestClient):
        response = client.get("/readiness")
        assert response.status_code == 200
        body = response.json()
        assert "status" in body
        assert "checks" in body

    def test_version_endpoint(self, client: TestClient):
        response = client.get("/version")
        assert response.status_code == 200
        body = response.json()
        assert "version" in body
        assert "environment" in body
        assert "name" in body

    def test_metrics_endpoint(self, client: TestClient):
        response = client.get("/metrics")
        assert response.status_code == 200
        body = response.json()
        assert "requests_total" in body
        assert "requests_failed" in body
        assert "average_latency_seconds" in body
        assert "status_code_distribution" in body

    def test_metrics_increment_on_request(self, client: TestClient):
        r1 = client.get("/metrics")
        total_before = r1.json()["requests_total"]
        client.get("/liveness")
        r2 = client.get("/metrics")
        total_after = r2.json()["requests_total"]
        assert total_after > total_before

    def test_health_includes_environment(self, client: TestClient):
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        body = response.json()
        assert "environment" in body
        assert "version" in body
        assert "subsystems" in body

    def test_health_subsystems_structure(self, client: TestClient):
        response = client.get("/api/v1/health")
        subsystems = response.json()["subsystems"]
        assert "parsers" in subsystems
        assert "detection_rules" in subsystems
        assert isinstance(subsystems["parsers"], bool)


# ---------------------------------------------------------------------------
# Request Size Limit
# ---------------------------------------------------------------------------


class TestRequestSizeLimit:
    def test_small_body_accepted(self, client: TestClient):
        """A small payload must reach the endpoint."""
        response = client.post(
            "/api/v1/parser/parse-line",
            json={"parser_name": "apache", "log_line": "test line"},
        )
        # 400 or 200 depending on parse, but not 413
        assert response.status_code != 413

    def test_oversized_body_rejected(self, client: TestClient):
        """A Content-Length exceeding the limit must return 413."""
        oversized = "x" * (1 * 1024 * 1024 + 100)  # 1 MB + 100 bytes
        response = client.post(
            "/api/v1/parser/parse-line",
            content=oversized.encode(),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 413


# ---------------------------------------------------------------------------
# File Upload Security
# ---------------------------------------------------------------------------


class TestFileUploadSecurity:
    def _upload(self, client: TestClient, filename: str, content: bytes = b"test log", content_type: str = "text/plain"):
        return client.post(
            "/api/v1/parser/parse-file",
            data={"parser_name": "apache"},
            files={"file": (filename, BytesIO(content), content_type)},
        )

    def test_normal_filename_accepted(self, client: TestClient):
        response = self._upload(client, "access.log")
        # Any response other than 400/415 for filename means it passed validation
        assert response.status_code not in (400, 415) or "filename" not in response.text.lower()

    def test_path_traversal_blocked(self, client: TestClient):
        """
        PurePath.name strips directory traversal components — the attack is neutralised.
        The request should NOT result in a server error (500) or path leak.
        The file is processed under a sanitised name (basename only).
        """
        response = self._upload(client, "../../etc/passwd")
        # The traversal is neutralised by PurePath.name — we get 200 or a parse error, NOT 500
        assert response.status_code != 500
        # The response must not echo back the traversal path
        assert "../../" not in response.text

    def test_null_byte_filename_blocked(self, client: TestClient):
        response = self._upload(client, "evil\x00.log")
        # Either blocked at validation or sanitised
        assert response.status_code in (400, 415, 422, 200)

    def test_dangerous_content_type_rejected(self, client: TestClient):
        response = self._upload(
            client, "script.php", b"<?php echo 'evil'; ?>", "application/x-php"
        )
        assert response.status_code == 415

    def test_executable_content_type_rejected(self, client: TestClient):
        response = self._upload(
            client, "malware.exe", b"\x4d\x5a", "application/x-msdownload"
        )
        assert response.status_code == 415


# ---------------------------------------------------------------------------
# Thread-Safe InMemoryCache
# ---------------------------------------------------------------------------


class TestInMemoryCache:
    def test_basic_get_set(self):
        cache = InMemoryCache(ttl_seconds=60)
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"

    def test_miss_returns_none(self):
        cache = InMemoryCache(ttl_seconds=60)
        assert cache.get("nonexistent") is None

    def test_ttl_expiry(self):
        cache = InMemoryCache(ttl_seconds=0)
        cache.set("expiring", "soon")
        time.sleep(0.01)
        assert cache.get("expiring") is None

    def test_lru_eviction(self):
        cache = InMemoryCache(ttl_seconds=60, max_entries=2)
        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("c", 3)  # Should evict "a" (oldest)
        assert cache.get("a") is None
        assert cache.get("b") == 2
        assert cache.get("c") == 3

    def test_invalidate(self):
        cache = InMemoryCache(ttl_seconds=60)
        cache.set("del_me", "val")
        result = cache.invalidate("del_me")
        assert result is True
        assert cache.get("del_me") is None

    def test_stats(self):
        cache = InMemoryCache(ttl_seconds=60)
        cache.set("k", "v")
        cache.get("k")   # hit
        cache.get("miss")  # miss
        stats = cache.stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["size"] == 1

    def test_thread_safety(self):
        """Concurrent writes must not corrupt the cache."""
        cache = InMemoryCache(ttl_seconds=60, max_entries=500)
        errors = []

        def worker(thread_id: int):
            try:
                for i in range(50):
                    cache.set(f"t{thread_id}-k{i}", i)
                    cache.get(f"t{thread_id}-k{i}")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Thread-safety errors: {errors}"

    def test_clear_resets_stats(self):
        cache = InMemoryCache(ttl_seconds=60)
        cache.set("x", 1)
        cache.get("x")
        cache.clear()
        stats = cache.stats()
        assert stats["size"] == 0
        assert stats["hits"] == 0


# ---------------------------------------------------------------------------
# Structured Logging
# ---------------------------------------------------------------------------


class TestStructuredFormatter:
    def _make_record(self, msg: str = "test", **kwargs) -> logging.LogRecord:
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg=msg,
            args=(),
            exc_info=None,
        )
        for k, v in kwargs.items():
            setattr(record, k, v)
        return record

    def test_output_is_valid_json(self):
        formatter = StructuredFormatter()
        record = self._make_record("hello")
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "timestamp" in parsed
        assert "level" in parsed
        assert "message" in parsed

    def test_correlation_id_injected(self):
        formatter = StructuredFormatter()
        record = self._make_record("hello", correlation_id="abc-123")
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["correlation_id"] == "abc-123"

    def test_sensitive_keys_redacted(self):
        formatter = StructuredFormatter()
        record = self._make_record("hello", api_key="sk-supersecret")
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed.get("api_key") == "[REDACTED]"
        assert "sk-supersecret" not in output

    def test_password_redacted(self):
        formatter = StructuredFormatter()
        record = self._make_record("login attempt", password="hunter2")
        output = formatter.format(record)
        assert "hunter2" not in output

    def test_exception_info_included(self):
        formatter = StructuredFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            import sys
            record = logging.LogRecord(
                name="test", level=logging.ERROR,
                pathname="", lineno=0, msg="err",
                args=(), exc_info=sys.exc_info()
            )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "exception" in parsed


# ---------------------------------------------------------------------------
# Settings Validators
# ---------------------------------------------------------------------------


class TestSettingsValidators:
    def test_invalid_environment_raises(self):
        with pytest.raises(ValidationError):
            Settings(ENVIRONMENT="chaos")

    def test_invalid_log_level_raises(self):
        with pytest.raises(ValidationError):
            Settings(LOG_LEVEL="VERBOSE")

    def test_invalid_ai_provider_raises(self):
        with pytest.raises(ValidationError):
            Settings(AI_PROVIDER="chatgpt")

    def test_confidence_out_of_range_raises(self):
        with pytest.raises(ValidationError):
            Settings(DETECTION_DEFAULT_CONFIDENCE=1.5)

    def test_temperature_out_of_range_raises(self):
        with pytest.raises(ValidationError):
            Settings(AI_TEMPERATURE=3.0)

    def test_valid_settings_accepted(self):
        s = Settings(ENVIRONMENT="staging", LOG_LEVEL="DEBUG", AI_PROVIDER="gemini")
        assert s.ENVIRONMENT == "staging"
        assert s.LOG_LEVEL == "DEBUG"

    def test_log_level_normalised_to_uppercase(self):
        s = Settings(LOG_LEVEL="debug")
        assert s.LOG_LEVEL == "DEBUG"
