"""LogSentry Cryptographic JWT Authentication Module.

Implements RFC 7519 compliant JSON Web Tokens pinned strictly to HMAC-SHA256 (HS256)
using PyJWT. Enforces issuer, audience, subject, expiration, issuance, token type,
and tenant binding.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from jwt.exceptions import (
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    InvalidTokenError,
    MissingRequiredClaimError,
    PyJWTError,
)

from app.config.settings import settings

JWT_ALGORITHM = "HS256"
JWT_ISSUER = "logsentry-siem"
JWT_AUDIENCE = "logsentry-soc"
TOKEN_TYPE_ACCESS = "access"

PROTECTED_CLAIMS = frozenset(
    {"iss", "aud", "sub", "role", "tenant_id", "iat", "exp", "typ"}
)


def get_secret_key() -> str:
    """Retrieves validated SECRET_KEY from application configuration."""
    key = getattr(settings, "SECRET_KEY", None)
    is_prod_or_staging = getattr(settings, "ENVIRONMENT", "development") in (
        "production",
        "staging",
    )
    if is_prod_or_staging:
        if (
            not key
            or key == "logsentry-insecure-dev-secret-key-min-32-chars-2026!"
            or "CHANGE_ME" in key
            or len(key) < 32
        ):
            raise RuntimeError(
                "Production/Staging violation: SECRET_KEY must be a securely provisioned key with >= 32 characters."
            )
    return key or "logsentry-insecure-dev-secret-key-min-32-chars-2026!"


def create_access_token(
    user_id: str,
    role: str,
    tenant_id: str = "default",
    email: str | None = None,
    expires_delta_minutes: int | None = None,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """
    Creates a cryptographically signed RFC 7519 HS256 JWT access token.

    Mandatory claims embedded:
      - iss: logsentry-siem
      - aud: logsentry-soc
      - sub: user_id
      - role: role
      - tenant_id: tenant_id
      - typ: access
      - iat: UTC issuance timestamp
      - exp: UTC expiration timestamp
    """
    now = datetime.now(UTC)
    minutes = (
        expires_delta_minutes
        if expires_delta_minutes is not None
        else getattr(settings, "AUTH_TOKEN_EXPIRE_MINUTES", 120)
    )
    expire = now + timedelta(minutes=minutes)

    payload: dict[str, Any] = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "sub": str(user_id),
        "email": email or f"{user_id}@logsentry.corp",
        "role": str(role),
        "tenant_id": str(tenant_id),
        "typ": TOKEN_TYPE_ACCESS,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }

    # Safe extra claims — prevent overwriting core security claims
    if extra_claims:
        for k, v in extra_claims.items():
            if k not in PROTECTED_CLAIMS:
                payload[k] = v

    secret = get_secret_key()
    return jwt.encode(
        payload,
        secret,
        algorithm=JWT_ALGORITHM,
        headers={"typ": "JWT", "alg": JWT_ALGORITHM},
    )


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Decodes and validates an HS256 JWT access token.

    Enforces:
      - Algorithm whitelist: strictly HS256 (rejects 'none', asymmetric, etc.)
      - Issuer validation: 'logsentry-siem'
      - Audience validation: 'logsentry-soc'
      - Expiration and clock-skew checking
      - Mandatory claims: sub, role, tenant_id, typ, iat, exp
      - Token type: strictly 'access'

    Raises:
      ValueError: on any signature mismatch, malformed payload, claim violation, or expiration.
    """
    if not token or not isinstance(token, str):
        raise ValueError("Invalid token: token must be a non-empty string")

    clean_token = token.strip()
    if clean_token.count(".") != 2:
        raise ValueError("Invalid JWT format: token must contain 3 dot-separated parts")

    secret = get_secret_key()

    try:
        # First verify unverified header to ensure alg is specifically HS256
        unverified_header = jwt.get_unverified_header(clean_token)
        if unverified_header.get("alg") != JWT_ALGORITHM:
            raise ValueError(
                f"Unsupported JWT algorithm '{unverified_header.get('alg')}'. Pinned to '{JWT_ALGORITHM}'."
            )
        if unverified_header.get("typ") != "JWT":
            raise ValueError(
                f"Invalid JWT type in header '{unverified_header.get('typ')}'. Expected 'JWT'."
            )

        payload = jwt.decode(
            clean_token,
            secret,
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
                "require": ["exp", "iat", "sub", "role", "tenant_id"],
            },
            leeway=10,  # 10s leeway for minor clock skew
        )

        # Validate token type claim
        if payload.get("typ") != TOKEN_TYPE_ACCESS:
            raise ValueError(
                f"Invalid token type '{payload.get('typ')}'. Expected '{TOKEN_TYPE_ACCESS}'."
            )

        return payload

    except ExpiredSignatureError:
        raise ValueError("JWT access token has expired")
    except ImmatureSignatureError:
        raise ValueError("JWT issued in the future (clock skew error)")
    except InvalidAudienceError:
        raise ValueError(f"Invalid JWT audience. Expected '{JWT_AUDIENCE}'")
    except InvalidIssuerError:
        raise ValueError(f"Invalid JWT issuer. Expected '{JWT_ISSUER}'")
    except MissingRequiredClaimError as e:
        raise ValueError(f"Missing mandatory JWT claim: {e}")
    except (InvalidSignatureError, InvalidTokenError) as e:
        raise ValueError(f"JWT signature verification failed: {e}")
    except PyJWTError as e:
        raise ValueError(f"JWT verification error: {e}")
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f"Corrupt or invalid JWT: {e}")
