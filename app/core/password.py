"""LogSentry Password Security and Hashing Module.

Uses Argon2id (RFC 9106) via argon2-cffi.
Argon2id is the state-of-the-art memory-hard password hashing function,
resistant to GPU, FPGA, and ASIC side-channel and brute-force cracking.
"""

import logging

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

logger = logging.getLogger(__name__)

# RFC 9106 recommended parameters: memory 64 MiB, time cost 3, parallelism 4
_ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def hash_password(plain_password: str) -> str:
    """Hashes a plaintext password using Argon2id with cryptographically random salt."""
    if not plain_password:
        raise ValueError("Password cannot be empty")
    return _ph.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plaintext password against an Argon2id hash.
    Performs constant-time comparison to prevent timing side-channel attacks.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        return _ph.verify(hashed_password, plain_password)
    except (VerifyMismatchError, InvalidHashError):
        return False
    except Exception as e:
        logger.warning(f"Unexpected error during password verification: {e}")
        return False


def needs_rehash(hashed_password: str) -> bool:
    """Checks whether the password hash was generated with older/weaker parameters."""
    try:
        return _ph.check_needs_rehash(hashed_password)
    except Exception:
        return True
