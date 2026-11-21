"""LogSentry Cryptographic JWT Authentication Module.

Implements RFC 7519 compliant JSON Web Tokens (HS256) using standard-library cryptography.
Zero external dependencies, fast, thread-safe, and secure.
"""

import base64
import hashlib
import hmac
import json
import time
from typing import Any

from app.config.settings import settings

JWT_ALGORITHM = "HS256"
# Default secret key from settings or fallback to standard secure key
SECRET_KEY = getattr(
    settings, "SECRET_KEY", "logsentry-enterprise-soc-jwt-secret-key-2026"
)


def _base64url_encode(data: bytes) -> str:
    """Encodes bytes to URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _base64url_decode(data: str) -> bytes:
    """Decodes URL-safe base64 string, restoring padding if needed."""
    rem = len(data) % 4
    if rem > 0:
        data += "=" * (4 - rem)
    return base64.urlsafe_b64decode(data.encode("utf-8"))


def create_access_token(
    user_id: str,
    role: str,
    tenant_id: str = "default",
    email: str | None = None,
    expires_delta_minutes: int = 120,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """Creates a cryptographically signed HS256 JWT access token."""
    now = int(time.time())
    header = {"alg": JWT_ALGORITHM, "typ": "JWT"}
    payload = {
        "sub": user_id,
        "email": email or f"{user_id}@logsentry.corp",
        "role": role,
        "tenant_id": tenant_id,
        "iat": now,
        "exp": now + (expires_delta_minutes * 60),
    }
    if extra_claims:
        payload.update(extra_claims)

    header_b64 = _base64url_encode(
        json.dumps(header, separators=(",", ":")).encode("utf-8")
    )
    payload_b64 = _base64url_encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )

    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(
        SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256
    ).digest()
    sig_b64 = _base64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Decodes and validates an HS256 JWT access token.
    Raises ValueError on invalid token format, signature mismatch, or expiration.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format: token must contain 3 dot-separated parts")

    header_b64, payload_b64, sig_b64 = parts

    # Verify signature
    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected_sig = hmac.new(
        SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256
    ).digest()
    actual_sig = _base64url_decode(sig_b64)

    if not hmac.compare_digest(expected_sig, actual_sig):
        raise ValueError("JWT signature verification failed: invalid token")

    # Parse payload
    try:
        payload_bytes = _base64url_decode(payload_b64)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Corrupt JWT payload: {e}")

    # Check expiration
    exp = payload.get("exp")
    if exp and int(time.time()) > int(exp):
        raise ValueError("JWT access token has expired")

    return payload
