"""
LogSentry — Cryptographic Privacy & PII Encryption Services
===========================================================
Provides authenticated encryption at rest (AES-256-GCM) with HKDF key derivation
for sensitive observable indicators (email addresses, telephone numbers).
Guarantees zero-knowledge PII protection in the persistence layer while enabling
authorized unmasking for vetted security operations personnel.
"""

import base64
import os
from functools import lru_cache

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config.settings import settings

HKDF_PII_SALT = b"LogSentry-PII-Encryption-Salt-v1"
HKDF_PII_INFO = b"tiore-pii-at-rest"


@lru_cache(maxsize=1)
def _get_aes_gcm_cipher() -> AESGCM:
    """
    Derives a cryptographically strong 256-bit symmetric key using HKDF
    from the application SECRET_KEY (or dedicated PII_ENCRYPTION_KEY).
    """
    secret = getattr(settings, "PII_ENCRYPTION_KEY", None) or settings.SECRET_KEY
    if not secret:
        raise ValueError(
            "Encryption requires a configured SECRET_KEY or PII_ENCRYPTION_KEY"
        )

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=HKDF_PII_SALT,
        info=HKDF_PII_INFO,
    )
    key = hkdf.derive(secret.encode("utf-8"))
    return AESGCM(key)


def encrypt_pii(plaintext: str) -> str:
    """
    Encrypts sensitive PII using AES-256-GCM with a freshly generated 96-bit nonce.
    Returns URL-safe base64 string formatted as nonce || ciphertext || tag.
    """
    if not plaintext:
        return ""
    cipher = _get_aes_gcm_cipher()
    nonce = os.urandom(12)
    ciphertext = cipher.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt_pii(token: str) -> str:
    """
    Decrypts and authenticates AES-256-GCM ciphertext.
    Raises ValueError if ciphertext is tampered with, corrupted, or invalid.
    """
    if not token:
        return ""
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii"))
        if len(raw) < 28:  # 12-byte nonce + 16-byte GCM tag minimum
            raise ValueError("Ciphertext payload too short")
        nonce = raw[:12]
        ciphertext = raw[12:]
        cipher = _get_aes_gcm_cipher()
        return cipher.decrypt(nonce, ciphertext, None).decode("utf-8")
    except Exception as exc:
        raise ValueError(f"Failed to decrypt PII: {exc}") from exc
