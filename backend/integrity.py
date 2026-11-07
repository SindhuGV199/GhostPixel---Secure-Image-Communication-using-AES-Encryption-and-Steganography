"""
GhostPixel - Transmission Integrity Verification Module
Provides comprehensive end-to-end integrity diagnostics:
1. Steganographic carrier and envelope extraction verification
2. Pre-decryption SHA-256 payload digest verification
3. AES-256-GCM cryptographic authentication tag verification
4. Precise diagnostic distinction between data corruption, incorrect password,
   unsupported image format (JPEG/WebP), cropping, resizing, and extraction failure.
"""

import io
import time
import struct
from typing import Dict, Any, Optional, Tuple, Union
import numpy as np
from PIL import Image

from backend.encryption import (
    decrypt_message,
    unpack_encrypted_payload,
    DecryptionError,
    TAG_SIZE,
    SALT_SIZE,
    NONCE_SIZE
)
from backend.hashing import compute_sha256, verify_sha256
from backend.steganography import (
    MAGIC_BYTES,
    HEADER_SIZE,
    MIN_PAYLOAD_SIZE,
    SteganographyError
)
from backend.image_processing import (
    load_image,
    calculate_image_capacity,
    ImageProcessingError,
    SUPPORTED_FORMATS
)


class TransmissionVerificationError(Exception):
    """Base exception for transmission integrity failures."""
    def __init__(self, message: str, code: str, stage: str):
        super().__init__(message)
        self.code = code
        self.stage = stage


class CarrierCorruptionError(TransmissionVerificationError):
    """Raised when carrier image has been compressed, resized, cropped, or corrupted."""
    def __init__(self, message: str, code: str = "ERR_CARRIER_CORRUPTED"):
        super().__init__(message, code=code, stage="CARRIER_EXTRACTION")


class PayloadIntegrityError(TransmissionVerificationError):
    """Raised when SHA-256 digest of extracted payload does not match stored hash."""
    def __init__(self, message: str, code: str = "ERR_SHA256_MISMATCH"):
        super().__init__(message, code=code, stage="SHA256_VERIFICATION")


class AuthenticationFailureError(TransmissionVerificationError):
    """Raised when AES-GCM tag verification fails (wrong password or ciphertext alteration)."""
    def __init__(self, message: str, code: str = "ERR_AES_GCM_AUTH_FAILED"):
        super().__init__(message, code=code, stage="AES_GCM_AUTHENTICATION")


class FormatUnsupportedError(TransmissionVerificationError):
    """Raised when an unsupported image format (such as JPEG, GIF, or WebP) is provided."""
    def __init__(self, message: str, code: str = "ERR_UNSUPPORTED_FORMAT"):
        super().__init__(message, code=code, stage="FORMAT_VALIDATION")


def inspect_image_source(source: Union[bytes, bytearray, io.BytesIO, str]) -> Dict[str, Any]:
    """
    Inspects raw image source to diagnose format or compression artifacts
    before attempting cryptographic extraction.
    """
    if isinstance(source, (bytes, bytearray)):
        raw_bytes = bytes(source)
    elif isinstance(source, io.BytesIO):
        raw_bytes = source.getvalue()
    elif isinstance(source, str):
        with open(source, "rb") as f:
            raw_bytes = f.read()
    else:
        raw_bytes = b""

    # Detect common image signatures
    is_jpeg = raw_bytes.startswith(b"\xff\xd8\xff")
    is_png = raw_bytes.startswith(b"\x89PNG\r\n\x1a\n")
    is_bmp = raw_bytes.startswith(b"BM")
    is_gif = raw_bytes.startswith(b"GIF87a") or raw_bytes.startswith(b"GIF89a")
    is_webp = len(raw_bytes) > 12 and raw_bytes[0:4] == b"RIFF" and raw_bytes[8:12] == b"WEBP"

    detected_type = "UNKNOWN"
    if is_png:
        detected_type = "PNG"
    elif is_bmp:
        detected_type = "BMP"
    elif is_jpeg:
        detected_type = "JPEG"
    elif is_gif:
        detected_type = "GIF"
    elif is_webp:
        detected_type = "WEBP"

    return {
        "detected_type": detected_type,
        "is_lossless": detected_type in SUPPORTED_FORMATS,
        "is_jpeg": is_jpeg,
        "is_webp": is_webp,
        "raw_size": len(raw_bytes)
    }


def verify_transmission(
    image_source: Union[bytes, io.BytesIO, str, Image.Image],
    password: Optional[str] = None
) -> Dict[str, Any]:
    """
    Executes a comprehensive, 4-stage Transmission Integrity Verification:
    
    Stage 1: Carrier & Envelope Extraction
             - Validates lossless format (rejects JPEG/WebP with specific diagnosis).
             - Verifies magic signature ('GPX1') and payload envelope length.
             - Distinguishes resizing/cropping/compression destruction from valid carriers.
             
    Stage 2: SHA-256 Payload Hash Integrity
             - Reconstructs exact extracted encrypted payload (salt + nonce + tag + ciphertext).
             - Computes fresh SHA-256 digest.
             - Compares against stored digest using constant-time comparison.
             - Halts if tampered or corrupted.
             
    Stage 3: AES-256-GCM Cryptographic Authentication (if password provided)
             - Derives 256-bit key from salt and password via PBKDF2-HMAC-SHA256 (100k rounds).
             - Decrypts with AES-256-GCM and verifies 128-bit authentication tag.
             - Rejects wrong passwords or tag manipulation with authentication failure warnings.
             
    Stage 4: Overall Transmission Verdict
             - Synthesizes comprehensive diagnostic scorecard.
             - Guarantees partial plaintext is NEVER returned on any failure.
    """
    t_start = time.perf_counter()

    report: Dict[str, Any] = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "stage_1_extraction": {
            "status": "PENDING",
            "format": "UNKNOWN",
            "dimensions": None,
            "magic_verified": False,
            "payload_bytes": 0,
            "details": ""
        },
        "stage_2_sha256": {
            "status": "PENDING",
            "calculated_hash": None,
            "stored_hash": None,
            "hash_match": False,
            "verification_time_ms": 0.0,
            "details": ""
        },
        "stage_3_aes_gcm": {
            "status": "NOT_REQUESTED" if not password else "PENDING",
            "tag_verified": False,
            "salt_hex": None,
            "nonce_hex": None,
            "tag_hex": None,
            "ciphertext_bytes": 0,
            "auth_time_ms": 0.0,
            "details": ""
        },
        "overall_integrity": {
            "verdict": "FAILED",
            "code": "INIT",
            "is_secure": False,
            "can_decrypt": False,
            "summary": "",
            "diagnostic_recommendation": ""
        },
        "recovered_message": None
    }

    # -------------------------------------------------------------
    # STAGE 1: Carrier & Envelope Extraction
    # -------------------------------------------------------------
    try:
        # Pre-check raw bytes if available to detect JPEG / lossy formats immediately
        if not isinstance(image_source, Image.Image):
            src_info = inspect_image_source(image_source)
            if src_info["is_jpeg"]:
                raise FormatUnsupportedError(
                    "Uploaded file is a JPEG image. JPEG applies lossy Discrete Cosine Transform (DCT) "
                    "compression that permanently overwrites least significant bits. "
                    "Please upload the original uncompressed PNG file.",
                    code="ERR_FORMAT_JPEG"
                )
            elif src_info["detected_type"] not in SUPPORTED_FORMATS and src_info["detected_type"] != "UNKNOWN":
                raise FormatUnsupportedError(
                    f"Unsupported image format: '{src_info['detected_type']}'. GhostPixel requires lossless PNG or BMP carriers.",
                    code=f"ERR_FORMAT_{src_info['detected_type']}"
                )

        if isinstance(image_source, Image.Image):
            pil_img = image_source.convert("RGB")
            img_format = "PNG"
        else:
            pil_img, img_format = load_image(image_source)

        report["stage_1_extraction"]["format"] = img_format
        report["stage_1_extraction"]["dimensions"] = f"{pil_img.width}x{pil_img.height}"

        width, height = pil_img.size
        cap_info = calculate_image_capacity(width, height, 3)
        total_usable_bytes = cap_info["usable_capacity_bytes"]

        if total_usable_bytes < HEADER_SIZE:
            raise CarrierCorruptionError(
                f"Image dimensions ({width}x{height}) are too small to contain a GhostPixel envelope ({total_usable_bytes} bytes usable; minimum {HEADER_SIZE} bytes needed). "
                "The image may have been cropped or resized down.",
                code="ERR_IMAGE_TOO_SMALL"
            )

        img_arr = np.array(pil_img, dtype=np.uint8)
        flat = img_arr.reshape(-1)

        # Extract 64-bit header
        header_bits = flat[: HEADER_SIZE * 8] & 1
        header_bytes = np.packbits(header_bits).tobytes()

        magic = header_bytes[:4]
        if magic != MAGIC_BYTES:
            # Diagnose reason for missing magic signature
            raise CarrierCorruptionError(
                "No GhostPixel signature ('GPX1') found in this image. "
                "Probable causes: (1) Image was recompressed to lossy format (e.g., WhatsApp/social media compression), "
                "(2) Image was resized or cropped in transit, or (3) This is an ordinary image without hidden data.",
                code="ERR_MAGIC_NOT_FOUND"
            )

        report["stage_1_extraction"]["magic_verified"] = True

        payload_len = struct.unpack(">I", header_bytes[4:8])[0]
        max_allowable = total_usable_bytes - HEADER_SIZE

        if payload_len < MIN_PAYLOAD_SIZE or payload_len > max_allowable:
            raise CarrierCorruptionError(
                f"Extracted payload length ({payload_len:,} bytes) is invalid (expected between {MIN_PAYLOAD_SIZE} and {max_allowable:,} bytes). "
                "The header bits have been corrupted or the image was cropped.",
                code="ERR_HEADER_LENGTH_CORRUPTED"
            )

        total_bits = (HEADER_SIZE + payload_len) * 8
        if total_bits > len(flat):
            raise CarrierCorruptionError(
                f"Incomplete payload: header specifies {payload_len:,} bytes, but image can only provide {len(flat)//8 - HEADER_SIZE:,} bytes. "
                "The image was likely cropped or truncated.",
                code="ERR_TRUNCATED_CARRIER"
            )

        payload_bits = flat[HEADER_SIZE * 8 : total_bits] & 1
        extracted_bytes = np.packbits(payload_bits).tobytes()

        if len(extracted_bytes) != payload_len:
            raise CarrierCorruptionError(
                f"Extraction truncated: read {len(extracted_bytes)} bytes, expected {payload_len} bytes.",
                code="ERR_EXTRACTION_TRUNCATED"
            )

        stored_hash = extracted_bytes[:32]
        encrypted_payload = extracted_bytes[32:]

        salt, nonce, tag, ciphertext = unpack_encrypted_payload(encrypted_payload)

        report["stage_1_extraction"]["status"] = "SUCCESS"
        report["stage_1_extraction"]["payload_bytes"] = payload_len
        report["stage_1_extraction"]["details"] = (
            f"Successfully reconstructed {payload_len:,} bytes payload envelope with valid GPX1 signature."
        )

    except FormatUnsupportedError as e:
        report["stage_1_extraction"]["status"] = "UNSUPPORTED_FORMAT"
        report["stage_1_extraction"]["details"] = str(e)
        report["overall_integrity"].update({
            "verdict": "FORMAT_UNSUPPORTED",
            "code": e.code,
            "is_secure": False,
            "can_decrypt": False,
            "summary": "Unsupported image format rejected. Lossy formats permanently destroy hidden pixel data.",
            "diagnostic_recommendation": "Request the sender to send the carrier as an original, uncompressed PNG document."
        })
        return report

    except CarrierCorruptionError as e:
        report["stage_1_extraction"]["status"] = "CARRIER_CORRUPTED"
        report["stage_1_extraction"]["details"] = str(e)
        report["overall_integrity"].update({
            "verdict": "CARRIER_CORRUPTED",
            "code": e.code,
            "is_secure": False,
            "can_decrypt": False,
            "summary": f"Carrier extraction failed: {str(e)}",
            "diagnostic_recommendation": "Verify the image was not cropped, resized, or sent through a compression channel (like social media photos)."
        })
        return report

    except Exception as e:
        report["stage_1_extraction"]["status"] = "EXTRACTION_FAILED"
        report["stage_1_extraction"]["details"] = f"Unexpected extraction error: {str(e)}"
        report["overall_integrity"].update({
            "verdict": "EXTRACTION_FAILED",
            "code": "ERR_UNKNOWN_EXTRACTION",
            "is_secure": False,
            "can_decrypt": False,
            "summary": f"Extraction error: {str(e)}",
            "diagnostic_recommendation": "Ensure the image file is not corrupted."
        })
        return report

    # -------------------------------------------------------------
    # STAGE 2: SHA-256 Payload Hash Integrity Verification
    # -------------------------------------------------------------
    t_sha_0 = time.perf_counter()
    is_sha_valid, calculated_hex, stored_hex = verify_sha256(encrypted_payload, stored_hash)
    t_sha_elapsed = (time.perf_counter() - t_sha_0) * 1000.0

    report["stage_2_sha256"].update({
        "status": "VERIFIED" if is_sha_valid else "MISMATCH",
        "calculated_hash": calculated_hex,
        "stored_hash": stored_hex,
        "hash_match": is_sha_valid,
        "verification_time_ms": round(t_sha_elapsed, 4),
        "details": (
            "SHA-256 payload digest matches stored header perfectly (constant-time verification passed)."
            if is_sha_valid
            else "SHA-256 mismatch detected: Extracted encrypted payload differs from original digest. Data was modified, tampered with, or corrupted!"
        )
    })

    # Strict Gate: If SHA-256 verification fails, STOP immediately
    if not is_sha_valid:
        report["stage_3_aes_gcm"]["status"] = "HALTED_BY_SHA256_MISMATCH"
        report["stage_3_aes_gcm"]["details"] = "Decryption prohibited due to payload integrity failure."
        report["overall_integrity"].update({
            "verdict": "TRANSMISSION_CORRUPTED",
            "code": "ERR_SHA256_MISMATCH",
            "is_secure": False,
            "can_decrypt": False,
            "summary": (
                "Transmission Integrity Check Failed: SHA-256 digest mismatch. "
                "The image carrier pixels carrying the encrypted payload were altered, corrupted, or tampered with in transit."
            ),
            "diagnostic_recommendation": (
                "Do not attempt decryption. The carrier was modified in transit. Request an untouched PNG copy from the sender."
            )
        })
        return report

    # -------------------------------------------------------------
    # STAGE 3: AES-256-GCM Cryptographic Authentication Verification
    # -------------------------------------------------------------
    report["stage_3_aes_gcm"].update({
        "salt_hex": salt.hex(),
        "nonce_hex": nonce.hex(),
        "tag_hex": tag.hex(),
        "ciphertext_bytes": len(ciphertext)
    })

    if not password:
        report["stage_3_aes_gcm"]["status"] = "AWAITING_PASSWORD"
        report["stage_3_aes_gcm"]["details"] = "SHA-256 integrity verified. Enter passphrase to verify AES-GCM authentication."
        report["overall_integrity"].update({
            "verdict": "INTEGRITY_VERIFIED_AWAITING_AUTH",
            "code": "OK_AWAITING_AUTH",
            "is_secure": True,
            "can_decrypt": True,
            "summary": "Payload integrity verified via SHA-256. Passphrase required for AES-256-GCM authentication.",
            "diagnostic_recommendation": "Provide the correct passphrase to complete authenticated decryption."
        })
        return report

    t_aes_0 = time.perf_counter()
    try:
        decrypted_plaintext = decrypt_message(salt, nonce, tag, ciphertext, password)
        t_aes_elapsed = (time.perf_counter() - t_aes_0) * 1000.0

        report["stage_3_aes_gcm"].update({
            "status": "AUTHENTICATED",
            "tag_verified": True,
            "auth_time_ms": round(t_aes_elapsed, 2),
            "details": "AES-256-GCM 128-bit authentication tag verified successfully. Ciphertext authenticity confirmed."
        })

        report["recovered_message"] = decrypted_plaintext
        report["overall_integrity"].update({
            "verdict": "SECURE_AND_AUTHENTICATED",
            "code": "SUCCESS_AUTHENTICATED",
            "is_secure": True,
            "can_decrypt": True,
            "summary": "Full transmission integrity and authenticity verified. Message recovered with 100% fidelity.",
            "diagnostic_recommendation": "Transmission is secure and completely verified."
        })

    except DecryptionError as e:
        t_aes_elapsed = (time.perf_counter() - t_aes_0) * 1000.0
        report["stage_3_aes_gcm"].update({
            "status": "AUTH_FAILED",
            "tag_verified": False,
            "auth_time_ms": round(t_aes_elapsed, 2),
            "details": f"Authentication Failure: {str(e)}"
        })

        # Crucial security guarantee: Plaintext is NEVER exposed on auth failure
        report["recovered_message"] = None
        report["overall_integrity"].update({
            "verdict": "AUTHENTICATION_FAILED",
            "code": "ERR_AES_GCM_AUTH_FAILED",
            "is_secure": False,
            "can_decrypt": False,
            "summary": (
                "Cryptographic Authentication Failed: The derived key or 128-bit authentication tag is invalid. "
                "Either the passphrase is incorrect, or the ciphertext was altered by an active adversary."
            ),
            "diagnostic_recommendation": (
                "Verify that you entered the exact passphrase specified by the sender (passphrases are case-sensitive)."
            )
        })

    return report

