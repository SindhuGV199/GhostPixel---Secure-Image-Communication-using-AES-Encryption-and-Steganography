"""
GhostPixel - Hashing Module
Computes and verifies SHA-256 digests for payload integrity verification.
"""

import hashlib
import hmac
from typing import Tuple, Dict, Any


HASH_SIZE = 32  # SHA-256 outputs 256 bits = 32 bytes


def compute_sha256(data: bytes) -> bytes:
    """
    Computes standard SHA-256 raw digest (32 bytes).
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Data must be bytes or bytearray.")
    return hashlib.sha256(data).digest()


def compute_sha256_hex(data: bytes) -> str:
    """
    Computes standard SHA-256 hexadecimal string (64 characters).
    """
    return compute_sha256(data).hex()


def verify_sha256(data: bytes, expected_hash: bytes) -> Tuple[bool, str, str]:
    """
    Verifies data integrity by comparing its SHA-256 digest against the expected hash.
    Uses constant-time comparison to prevent timing attacks.
    Returns: (is_valid, calculated_hash_hex, expected_hash_hex)
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Data must be bytes or bytearray.")
    if not isinstance(expected_hash, (bytes, bytearray)):
        raise TypeError("Expected hash must be bytes or bytearray.")

    actual_hash = compute_sha256(data)
    is_valid = hmac.compare_digest(actual_hash, expected_hash)

    return is_valid, actual_hash.hex(), expected_hash.hex()


def verify_payload_integrity(encrypted_payload: bytes, expected_hash: bytes) -> Dict[str, Any]:
    """
    High-level integrity check returning formatted diagnostic information.
    """
    is_valid, calculated_hex, expected_hex = verify_sha256(encrypted_payload, expected_hash)
    
    return {
        "is_valid": is_valid,
        "calculated_hash": calculated_hex,
        "expected_hash": expected_hex,
        "status": "VERIFIED" if is_valid else "TAMPERED_OR_CORRUPTED",
        "message": (
            "Integrity verified: Extracted encrypted payload matches original SHA-256 digest perfectly."
            if is_valid
            else "Integrity check failed: Extracted payload has been modified, corrupted, or tampered with!"
        )
    }

