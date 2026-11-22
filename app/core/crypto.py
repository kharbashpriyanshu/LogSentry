"""
LogSentry — Cryptographic Privacy & PII Encryption Services
===========================================================
Provides authenticated encryption at rest (AES-256-GCM) with key-versioning,
rotation support, and HKDF key derivation for sensitive observables (emails, phones).
Guarantees zero-knowledge PII protection in the persistence layer while enabling
authorized unmasking for vetted security operations personnel.
"""

import base64
import hashlib
import hmac
import logging
import os
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config.settings import settings

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

HKDF_PII_SALT = b"LogSentry-PII-Encryption-Salt-v1"
HKDF_PII_INFO = b"tiore-pii-at-rest"
HKDF_HMAC_INFO = b"tiore-pii-hmac-key"

DEFAULT_KEY_VERSION = "v1"
_KEY_REGISTRY: dict[str, bytes] = {}


def register_pii_key(version: str, key_material: str | bytes) -> None:
    """Registers an explicit key material for a specific version (used in rotations/testing)."""
    if isinstance(key_material, str):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=HKDF_PII_SALT,
            info=f"tiore-pii-at-rest-{version}".encode(),
        )
        derived = hkdf.derive(key_material.encode("utf-8"))
    else:
        derived = key_material
    _KEY_REGISTRY[version] = derived


def get_key_for_version(version: str = DEFAULT_KEY_VERSION) -> bytes:
    """
    Retrieves or derives the 256-bit symmetric key for the requested key version.
    In production, PII_ENCRYPTION_KEY is strictly enforced.
    In development, derives deterministically from SECRET_KEY via HKDF.
    """
    if version in _KEY_REGISTRY:
        return _KEY_REGISTRY[version]

    if version == "v1":
        secret = getattr(settings, "PII_ENCRYPTION_KEY", None) or settings.SECRET_KEY
        if not secret:
            raise ValueError(
                "Encryption requires a configured PII_ENCRYPTION_KEY or SECRET_KEY"
            )

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=HKDF_PII_SALT,
            info=HKDF_PII_INFO,
        )
        return hkdf.derive(secret.encode("utf-8"))

    # Extensible for future key rotation versions (e.g. "v2")
    custom_key = os.environ.get(f"PII_ENCRYPTION_KEY_{version.upper()}")
    if custom_key:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=HKDF_PII_SALT,
            info=f"tiore-pii-at-rest-{version}".encode(),
        )
        return hkdf.derive(custom_key.encode("utf-8"))

    raise ValueError(f"Unknown or unconfigured PII encryption key version: {version}")


def get_pii_hmac_key() -> bytes:
    """
    Retrieves the dedicated HMAC key for observable fingerprinting.
    Eliminates hardcoded secrets by deriving deterministically from SECRET_KEY
    if dedicated PII_HMAC_KEY is unset in development.
    """
    configured = getattr(settings, "PII_HMAC_KEY", None)
    if configured:
        return configured.encode("utf-8")

    # Derive dedicated key from application secret
    secret = settings.SECRET_KEY
    if not secret:
        raise ValueError("HMAC derivation requires SECRET_KEY or PII_HMAC_KEY")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=HKDF_PII_SALT,
        info=HKDF_HMAC_INFO,
    )
    return hkdf.derive(secret.encode("utf-8"))


def encrypt_pii(plaintext: str, version: str = DEFAULT_KEY_VERSION) -> str:
    """
    Encrypts sensitive PII using AES-256-GCM with a freshly generated 96-bit nonce.
    Returns versioned token formatted as 'v1:<urlsafe_base64(nonce || ciphertext || tag)>'.
    """
    if not plaintext:
        return ""

    key = get_key_for_version(version)
    cipher = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = cipher.encrypt(nonce, plaintext.encode("utf-8"), None)
    payload_b64 = base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")
    return f"{version}:{payload_b64}"


def decrypt_pii(token: str) -> str:
    """
    Decrypts and authenticates AES-256-GCM ciphertext.
    Supports versioned tokens ('v1:...') as well as legacy unversioned tokens.
    Raises ValueError if ciphertext is tampered with, corrupted, or invalid.
    """
    if not token:
        return ""

    # Parse version prefix if present
    if ":" in token:
        version, payload = token.split(":", 1)
    else:
        version = DEFAULT_KEY_VERSION
        payload = token

    try:
        raw = base64.urlsafe_b64decode(payload.encode("ascii"))
        if len(raw) < 28:  # 12-byte nonce + 16-byte tag minimum
            raise ValueError("Ciphertext payload too short")

        nonce = raw[:12]
        ciphertext = raw[12:]
        key = get_key_for_version(version)
        cipher = AESGCM(key)
        return cipher.decrypt(nonce, ciphertext, None).decode("utf-8")
    except Exception as exc:
        raise ValueError(f"Failed to decrypt PII (version={version}): {exc}") from exc


def rotate_pii_encryption(token: str, target_version: str = DEFAULT_KEY_VERSION) -> str:
    """
    Unwraps ciphertext using its current key version and re-encrypts using target version.
    """
    plaintext = decrypt_pii(token)
    return encrypt_pii(plaintext, version=target_version)


def reencrypt_all_pii(db: "Session", target_version: str = "v2") -> int:
    """
    Idempotent database re-encryption operation.
    Scans all encrypted observables, decrypts them with their current versioned key,
    and re-encrypts them with target_version with round-trip verification.
    """
    from app.models.threat_intel import ObservableModel

    records = (
        db.query(ObservableModel)
        .filter(
            ObservableModel.encrypted_value.is_not(None),
            ~ObservableModel.encrypted_value.startswith(f"{target_version}:"),
        )
        .all()
    )

    reencrypted_count = 0
    for obs in records:
        if not obs.encrypted_value:
            continue
        original_plaintext = decrypt_pii(obs.encrypted_value)
        new_token = encrypt_pii(original_plaintext, version=target_version)
        # Assert round-trip decryption verification
        verified_decryption = decrypt_pii(new_token)
        if verified_decryption != original_plaintext:
            raise ValueError(
                f"Re-encryption round-trip failed on observable {obs.id}"
            )
        obs.encrypted_value = new_token
        reencrypted_count += 1

    if reencrypted_count > 0:
        db.commit()

    return reencrypted_count


def migrate_pii_hmac_fingerprints(
    db: "Session",
    new_hmac_key: bytes,
) -> int:
    """
    Safely migrates PII observable fingerprints (emails, phones) when rotating HMAC keys.
    Decrypts encrypted_value, computes new deterministic HMAC fingerprint, merges any
    duplicate tenant records, and updates observable fingerprints without losing event links.
    """
    from app.models.threat_intel import ObservableModel

    pii_records = (
        db.query(ObservableModel)
        .filter(ObservableModel.type.in_(["email", "phone"]))
        .all()
    )

    migrated_count = 0
    for obs in pii_records:
        if not obs.encrypted_value:
            continue

        plaintext = decrypt_pii(obs.encrypted_value)
        # Compute new HMAC-SHA256 fingerprint
        new_fp = hmac.new(
            new_hmac_key, plaintext.lower().strip().encode("utf-8"), hashlib.sha256
        ).hexdigest()

        if obs.fingerprint == new_fp:
            continue

        # Check if an observable with (tenant_id, new_fp) already exists
        existing = (
            db.query(ObservableModel)
            .filter(
                ObservableModel.tenant_id == obs.tenant_id,
                ObservableModel.fingerprint == new_fp,
                ObservableModel.id != obs.id,
            )
            .first()
        )

        if existing:
            # Re-point event links to existing observable
            from app.models.threat_intel import EventObservableModel, ThreatIntelMatchModel

            db.query(EventObservableModel).filter(
                EventObservableModel.observable_id == obs.id
            ).update({"observable_id": existing.id})
            db.query(ThreatIntelMatchModel).filter(
                ThreatIntelMatchModel.observable_id == obs.id
            ).update({"observable_id": existing.id})
            db.delete(obs)
        else:
            obs.fingerprint = new_fp

        migrated_count += 1

    if migrated_count > 0:
        db.commit()

    return migrated_count
