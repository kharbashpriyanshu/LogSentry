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
JWT_ISSUER = "logsentry-siem"
JWT_AUDIENCE = "logsentry-soc"

# Secret key validation: in non-dev, must meet minimum security entropy
_configured_key = getattr(
    settings, "SECRET_KEY", "logsentry-enterprise-soc-jwt-secret-key-2026"
)
if (
    getattr(settings, "ENVIRONMENT", "development") == "production"
    and _configured_key == "logsentry-enterprise-soc-jwt-secret-key-2026"
):
    raise RuntimeError(
        "Production security violation: Default JWT SECRET_KEY is not permitted in production."
    )

SECRET_KEY = _configured_key


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
    """Creates a cryptographically signed RFC 7519 HS256 JWT access token."""
    now = int(time.time())
    header = {"alg": JWT_ALGORITHM, "typ": "JWT"}

    # Base standard claims
    payload: dict[str, Any] = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "sub": user_id,
        "email": email or f"{user_id}@logsentry.corp",
        "role": role,
        "tenant_id": tenant_id,
        "iat": now,
        "exp": now + (expires_delta_minutes * 60),
    }

    # Safe extra claims — do NOT allow overwriting protected claims
    protected_claims = {"iss", "aud", "sub", "role", "tenant_id", "iat", "exp"}
    if extra_claims:
        for k, v in extra_claims.items():
            if k not in protected_claims:
                payload[k] = v

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
    Validates algorithm header, cryptographic HMAC signature, standard claims,
    and expiration timestamp.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format: token must contain 3 dot-separated parts")

    header_b64, payload_b64, sig_b64 = parts

    # Parse and validate header
    try:
        header_bytes = _base64url_decode(header_b64)
        header = json.loads(header_bytes.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Corrupt JWT header: {e}")

    if header.get("alg") != JWT_ALGORITHM:
        raise ValueError(
            f"Unsupported JWT algorithm '{header.get('alg')}'. Expected '{JWT_ALGORITHM}'."
        )
    if header.get("typ") != "JWT":
        raise ValueError(f"Invalid JWT type '{header.get('typ')}'. Expected 'JWT'.")

    # Verify signature
    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected_sig = hmac.new(
        SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256
    ).digest()
    try:
        actual_sig = _base64url_decode(sig_b64)
    except Exception as e:
        raise ValueError(f"Invalid JWT signature encoding: {e}")

    if not hmac.compare_digest(expected_sig, actual_sig):
        raise ValueError("JWT signature verification failed: invalid token")

    # Parse payload
    try:
        payload_bytes = _base64url_decode(payload_b64)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Corrupt JWT payload: {e}")

    # Enforce mandatory claims
    for required_claim in ("sub", "role", "iat", "exp"):
        if required_claim not in payload:
            raise ValueError(f"Missing mandatory JWT claim '{required_claim}'")

    # Validate issuer & audience when present
    if "iss" in payload and payload["iss"] != JWT_ISSUER:
        raise ValueError(
            f"Invalid JWT issuer '{payload['iss']}'. Expected '{JWT_ISSUER}'"
        )
    if "aud" in payload and payload["aud"] != JWT_AUDIENCE:
        raise ValueError(
            f"Invalid JWT audience '{payload['aud']}'. Expected '{JWT_AUDIENCE}'"
        )

    # Check expiration
    now = int(time.time())
    if now > int(payload["exp"]):
        raise ValueError("JWT access token has expired")

    # Check not-before / future timestamp
    if int(payload["iat"]) > now + 60:
        raise ValueError("JWT issued in the future (clock skew error)")

    return payload
