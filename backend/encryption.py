"""
GhostPixel - Encryption Module
Implements AES-256-GCM authenticated encryption and PBKDF2-HMAC-SHA256 key derivation.
"""

import os
import re
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag


# Cryptographic Constants
SALT_SIZE = 16       # 128-bit random salt
NONCE_SIZE = 12      # 96-bit random nonce standard for AES-GCM
TAG_SIZE = 16        # 128-bit authentication tag
KEY_SIZE = 32        # 256-bit AES key
PBKDF2_ITERATIONS = 100_000


class DecryptionError(Exception):
    """Raised when decryption fails due to wrong password or corrupted ciphertext."""
    pass


class EncryptionValidationError(Exception):
    """Raised when encryption input parameters are invalid."""
    pass


def evaluate_password_strength(password: str) -> Dict[str, Any]:
    """
    Evaluates password complexity and returns score, label, and criteria feedback.
    """
    if not password:
        return {
            "score": 0,
            "label": "Empty",
            "passed": False,
            "details": ["Password cannot be empty."]
        }

    checks = [
        (len(password) >= 8, "Minimum 8 characters"),
        (bool(re.search(r"[A-Z]", password)), "At least one uppercase letter (A-Z)"),
        (bool(re.search(r"[a-z]", password)), "At least one lowercase letter (a-z)"),
        (bool(re.search(r"\d", password)), "At least one number (0-9)"),
        (bool(re.search(r"[!@#$%^&*(),.?\":{}|<>\-_+=\[\]]", password)), "At least one special character")
    ]

    passed_count = sum(1 for passed, _ in checks if passed)
    details = [desc for passed, desc in checks if not passed]

    labels = {0: "Very Weak", 1: "Weak", 2: "Fair", 3: "Strong", 4: "Strong", 5: "Very Strong"}
    label = labels.get(passed_count, "Weak")

    return {
        "score": passed_count,
        "label": label,
        "passed": len(password) >= 6,  # Allow passwords >= 6 chars but warn if weak
        "details": details,
        "length": len(password)
    }


def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """
    Derive a 256-bit AES key from a passphrase and salt using PBKDF2-HMAC-SHA256.
    """
    if not isinstance(password, str) or not password:
        raise EncryptionValidationError("Password must be a non-empty string.")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != SALT_SIZE:
        raise EncryptionValidationError(f"Salt must be exactly {SALT_SIZE} bytes.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_message(plaintext: str, password: str) -> Dict[str, Any]:
    """
    Encrypts a plaintext string using AES-256-GCM.
    Returns salt, nonce, tag, ciphertext, and concatenated encrypted payload.
    """
    if not isinstance(plaintext, str) or len(plaintext.strip()) == 0:
        raise EncryptionValidationError("Secret message cannot be empty.")
    if not isinstance(password, str) or len(password) == 0:
        raise EncryptionValidationError("Password cannot be empty.")

    # Generate cryptographically secure random salt and nonce
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    # Derive 256-bit encryption key
    key = derive_key(password, salt)

    # Encrypt using AES-256-GCM
    aesgcm = AESGCM(key)
    plaintext_bytes = plaintext.encode("utf-8")
    
    # AESGCM.encrypt returns ciphertext + 16-byte authentication tag
    ct_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, associated_data=None)
    
    ciphertext = ct_with_tag[:-TAG_SIZE]
    tag = ct_with_tag[-TAG_SIZE:]

    # Structured payload: SALT (16B) + NONCE (12B) + TAG (16B) + CIPHERTEXT (NB)
    encrypted_payload = salt + nonce + tag + ciphertext

    return {
        "salt": salt,
        "nonce": nonce,
        "tag": tag,
        "ciphertext": ciphertext,
        "encrypted_payload": encrypted_payload,
        "salt_hex": salt.hex(),
        "nonce_hex": nonce.hex(),
        "tag_hex": tag.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "plaintext_len": len(plaintext_bytes),
        "payload_len": len(encrypted_payload)
    }


def decrypt_message(salt: bytes, nonce: bytes, tag: bytes, ciphertext: bytes, password: str) -> str:
    """
    Decrypts an AES-256-GCM ciphertext using the derived key and authenticates with tag.
    Raises DecryptionError if the password is wrong or ciphertext has been altered.
    """
    if not isinstance(password, str) or len(password) == 0:
        raise DecryptionError("Password cannot be empty.")
    if len(salt) != SALT_SIZE:
        raise DecryptionError(f"Invalid salt size: expected {SALT_SIZE} bytes, got {len(salt)}.")
    if len(nonce) != NONCE_SIZE:
        raise DecryptionError(f"Invalid nonce size: expected {NONCE_SIZE} bytes, got {len(nonce)}.")
    if len(tag) != TAG_SIZE:
        raise DecryptionError(f"Invalid tag size: expected {TAG_SIZE} bytes, got {len(tag)}.")

    try:
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        ct_with_tag = ciphertext + tag
        decrypted_bytes = aesgcm.decrypt(nonce, ct_with_tag, associated_data=None)
        return decrypted_bytes.decode("utf-8")
    except InvalidTag:
        raise DecryptionError("Decryption failed: Incorrect password or cryptographic authentication tag mismatch.")
    except UnicodeDecodeError:
        raise DecryptionError("Decryption failed: Output is not valid UTF-8 plaintext.")
    except Exception as e:
        raise DecryptionError(f"Decryption failed: {str(e)}")


def unpack_encrypted_payload(encrypted_payload: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    Unpacks a raw encrypted payload into (salt, nonce, tag, ciphertext).
    """
    min_len = SALT_SIZE + NONCE_SIZE + TAG_SIZE
    if len(encrypted_payload) < min_len:
        raise DecryptionError(f"Payload too short ({len(encrypted_payload)} bytes). Expected at least {min_len} bytes.")

    salt = encrypted_payload[:SALT_SIZE]
    nonce = encrypted_payload[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    tag = encrypted_payload[SALT_SIZE + NONCE_SIZE:SALT_SIZE + NONCE_SIZE + TAG_SIZE]
    ciphertext = encrypted_payload[SALT_SIZE + NONCE_SIZE + TAG_SIZE:]

    return salt, nonce, tag, ciphertext

