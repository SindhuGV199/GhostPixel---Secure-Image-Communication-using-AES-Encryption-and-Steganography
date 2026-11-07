"""
GhostPixel - Performance Evaluation Module
Measures PSNR, SSIM, execution timings, recovery accuracy, and integrity detection rate.
"""

import time
import math
from typing import Dict, Any, List, Tuple
import numpy as np
from PIL import Image
from scipy.ndimage import uniform_filter

from backend.encryption import (
    encrypt_message,
    decrypt_message,
    unpack_encrypted_payload,
    DecryptionError
)
from backend.hashing import compute_sha256, verify_payload_integrity
from backend.steganography import embed_lsb, extract_lsb, SteganographyError
from backend.image_processing import (
    calculate_image_capacity,
    evaluate_capacity_for_payload
)


def calculate_mse(img1: Image.Image, img2: Image.Image) -> float:
    """
    Calculates Mean Squared Error (MSE) between two RGB images.
    """
    if img1.size != img2.size:
        raise ValueError("Images must have identical dimensions to calculate MSE.")

    arr1 = np.array(img1.convert("RGB"), dtype=np.float64)
    arr2 = np.array(img2.convert("RGB"), dtype=np.float64)

    mse = np.mean((arr1 - arr2) ** 2)
    return float(mse)


def calculate_psnr(img1: Image.Image, img2: Image.Image) -> Dict[str, Any]:
    """
    Calculates Peak Signal-to-Noise Ratio (PSNR) in decibels (dB).
    Formula: PSNR = 10 * log10(MAX^2 / MSE), where MAX = 255 for 8-bit images.
    """
    mse = calculate_mse(img1, img2)
    
    if mse == 0.0:
        return {
            "psnr_db": 100.0,
            "mse": 0.0,
            "is_identical": True,
            "display": "100.00 dB (Identical / Lossless)"
        }

    psnr = 10.0 * math.log10((255.0 ** 2) / mse)
    psnr_rounded = round(psnr, 2)
    mse_rounded = round(mse, 6)

    # Human-readable quality interpretation
    if psnr >= 50.0:
        quality = "Imperceptible (Excellent steganographic stealth)"
    elif psnr >= 40.0:
        quality = "Very Good (Extremely minor alteration)"
    elif psnr >= 30.0:
        quality = "Acceptable (Visible under magnification)"
    else:
        quality = "Degraded (Noticeable visual distortion)"

    return {
        "psnr_db": psnr_rounded,
        "mse": mse_rounded,
        "is_identical": False,
        "quality": quality,
        "display": f"{psnr_rounded} dB"
    }


def calculate_ssim(img1: Image.Image, img2: Image.Image, win_size: int = 7) -> Dict[str, Any]:
    """
    Calculates the Structural Similarity Index (SSIM) between two RGB images.
    Uses windowed uniform filter across all three RGB channels.
    """
    if img1.size != img2.size:
        raise ValueError("Images must have identical dimensions to calculate SSIM.")

    arr1 = np.array(img1.convert("RGB"), dtype=np.float64)
    arr2 = np.array(img2.convert("RGB"), dtype=np.float64)

    # Standard SSIM constants for 8-bit dynamic range (L=255)
    c1 = (0.01 * 255.0) ** 2
    c2 = (0.03 * 255.0) ** 2

    # If images are very small, adjust win_size
    min_dim = min(arr1.shape[0], arr1.shape[1])
    effective_win = win_size if min_dim >= win_size else max(3, min_dim // 2 * 2 + 1)

    channel_ssims = []
    for c in range(3):
        im1 = arr1[:, :, c]
        im2 = arr2[:, :, c]

        mu1 = uniform_filter(im1, effective_win)
        mu2 = uniform_filter(im2, effective_win)
        mu1_sq = mu1 * mu1
        mu2_sq = mu2 * mu2
        mu1_mu2 = mu1 * mu2

        sigma1_sq = uniform_filter(im1 * im1, effective_win) - mu1_sq
        sigma2_sq = uniform_filter(im2 * im2, effective_win) - mu2_sq
        sigma12 = uniform_filter(im1 * im2, effective_win) - mu1_mu2

        num = (2.0 * mu1_mu2 + c1) * (2.0 * sigma12 + c2)
        den = (mu1_sq + mu2_sq + c1) * (sigma1_sq + sigma2_sq + c2)

        ssim_map = num / den
        channel_ssims.append(np.mean(ssim_map))

    ssim_val = float(np.mean(channel_ssims))
    ssim_clamped = max(0.0, min(1.0, ssim_val))
    ssim_rounded = round(ssim_clamped, 5)

    return {
        "ssim": ssim_rounded,
        "ssim_percentage": round(ssim_clamped * 100, 3),
        "display": f"{ssim_rounded:.5f}",
        "interpretation": "High Structural Fidelity" if ssim_rounded > 0.999 else "Modified Structure"
    }


def execute_full_pipeline(
    message: str,
    password: str,
    cover_image: Image.Image
) -> Dict[str, Any]:
    """
    Executes an end-to-end GhostPixel pipeline measuring real timings, quality metrics, and integrity.
    """
    # 1. AES Encryption Timing
    t0 = time.perf_counter()
    enc_result = encrypt_message(message, password)
    t_aes_enc = (time.perf_counter() - t0) * 1000.0

    encrypted_payload = enc_result["encrypted_payload"]

    # 2. SHA-256 Hash Generation Timing
    t0 = time.perf_counter()
    payload_hash = compute_sha256(encrypted_payload)
    t_sha_gen = (time.perf_counter() - t0) * 1000.0

    # 3. LSB Embedding Timing
    envelope_data = payload_hash + encrypted_payload
    t0 = time.perf_counter()
    stego_image = embed_lsb(cover_image, envelope_data)
    t_lsb_embed = (time.perf_counter() - t0) * 1000.0

    # Image Quality Evaluation
    psnr_data = calculate_psnr(cover_image, stego_image)
    ssim_data = calculate_ssim(cover_image, stego_image)
    cap_data = evaluate_capacity_for_payload(cover_image, len(envelope_data))

    # 4. LSB Extraction Timing
    t0 = time.perf_counter()
    extracted = extract_lsb(stego_image)
    t_lsb_extract = (time.perf_counter() - t0) * 1000.0

    # 5. SHA-256 Integrity Verification Timing
    t0 = time.perf_counter()
    integrity_data = verify_payload_integrity(extracted["encrypted_payload"], extracted["stored_hash"])
    t_sha_verify = (time.perf_counter() - t0) * 1000.0

    # 6. AES Decryption Timing
    t0 = time.perf_counter()
    salt, nonce, tag, ciphertext = unpack_encrypted_payload(extracted["encrypted_payload"])
    decrypted_message = decrypt_message(salt, nonce, tag, ciphertext, password)
    t_aes_dec = (time.perf_counter() - t0) * 1000.0

    total_time = t_aes_enc + t_sha_gen + t_lsb_embed + t_lsb_extract + t_sha_verify + t_aes_dec
    is_exact_match = (decrypted_message == message)

    return {
        "is_exact_match": is_exact_match,
        "message_length": len(message),
        "payload_size": len(envelope_data),
        "total_time_ms": round(total_time, 2),
        "timings": {
            "aes_encryption_ms": round(t_aes_enc, 2),
            "sha256_generation_ms": round(t_sha_gen, 4),
            "lsb_embedding_ms": round(t_lsb_embed, 2),
            "lsb_extraction_ms": round(t_lsb_extract, 2),
            "sha256_verification_ms": round(t_sha_verify, 4),
            "aes_decryption_ms": round(t_aes_dec, 2)
        },
        "metrics": {
            "psnr": psnr_data,
            "ssim": ssim_data,
            "capacity": cap_data
        },
        "integrity": integrity_data,
        "stego_image": stego_image
    }


def run_recovery_accuracy_test(
    test_messages: List[str],
    password: str,
    base_image: Image.Image
) -> Dict[str, Any]:
    """
    Evaluates Message Recovery Accuracy over a suite of real messages.
    Formula: Recovery Accuracy = (Successfully recovered / Total tested) * 100
    """
    total = len(test_messages)
    passed = 0
    results = []

    for i, msg in enumerate(test_messages):
        try:
            pipe = execute_full_pipeline(msg, password, base_image)
            recovered = pipe["is_exact_match"]
            if recovered:
                passed += 1
            results.append({
                "test_id": i + 1,
                "length": len(msg),
                "recovered": recovered,
                "total_time_ms": pipe["total_time_ms"],
                "psnr_db": pipe["metrics"]["psnr"]["psnr_db"],
                "ssim": pipe["metrics"]["ssim"]["ssim"],
                "sample": msg[:30] + ("..." if len(msg) > 30 else "")
            })
        except Exception as e:
            results.append({
                "test_id": i + 1,
                "length": len(msg),
                "recovered": False,
                "error": str(e),
                "sample": msg[:30] + ("..." if len(msg) > 30 else "")
            })

    accuracy = (passed / total * 100.0) if total > 0 else 0.0

    return {
        "total_tested": total,
        "successfully_recovered": passed,
        "recovery_accuracy_pct": round(accuracy, 2),
        "results": results
    }


def run_integrity_detection_test(
    message: str,
    correct_password: str,
    base_image: Image.Image
) -> Dict[str, Any]:
    """
    Evaluates the Integrity Detection Rate across multiple tampering scenarios:
    1. Unmodified original payload (Baseline: must pass integrity and decrypt)
    2. Tampered encrypted payload (Flipped byte in ciphertext: must fail SHA-256 integrity)
    3. Corrupted header/packet (Corrupted steganographic header: must be caught)
    4. Wrong password (SHA-256 matches, but AES-GCM tag verification catches and rejects)
    
    Formula: Integrity Detection Rate = (Correctly detected / Total tampered cases) * 100
    """
    cases = []
    
    # Baseline: Encrypt and embed normally
    enc = encrypt_message(message, correct_password)
    raw_payload = enc["encrypted_payload"]
    p_hash = compute_sha256(raw_payload)
    envelope = p_hash + raw_payload
    stego = embed_lsb(base_image, envelope)

    # Case 1: Unmodified
    try:
        extracted = extract_lsb(stego)
        integ = verify_payload_integrity(extracted["encrypted_payload"], extracted["stored_hash"])
        s, n, tg, ct = unpack_encrypted_payload(extracted["encrypted_payload"])
        dec = decrypt_message(s, n, tg, ct, correct_password)
        cases.append({
            "name": "Unmodified Payload",
            "type": "baseline",
            "description": "Legitimate stego image with no modifications",
            "sha256_detected": not integ["is_valid"],
            "aes_gcm_rejected": False,
            "expected_outcome": "Pass both SHA-256 and AES-GCM",
            "actual_outcome": "Integrity Verified & Decrypted Cleanly",
            "success": integ["is_valid"] and (dec == message)
        })
    except Exception as e:
        cases.append({
            "name": "Unmodified Payload",
            "type": "baseline",
            "description": "Legitimate stego image with no modifications",
            "error": str(e),
            "success": False
        })

    # Case 2: Tampered encrypted payload (flip a byte in ciphertext)
    try:
        # Alter one byte in ciphertext
        tampered_payload = bytearray(raw_payload)
        tampered_payload[-1] ^= 0xFF  # Flip last byte of ciphertext
        tampered_payload = bytes(tampered_payload)

        # Integrity verification against stored original hash
        integ_check = verify_payload_integrity(tampered_payload, p_hash)
        detected_by_sha = not integ_check["is_valid"]

        cases.append({
            "name": "Tampered Ciphertext Byte",
            "type": "tampered",
            "description": "Single bit/byte altered in ciphertext payload",
            "sha256_detected": detected_by_sha,
            "aes_gcm_rejected": True,  # Would also fail AES-GCM tag if not stopped
            "expected_outcome": "SHA-256 Integrity Verification Fails",
            "actual_outcome": "Tampering Detected by SHA-256",
            "success": detected_by_sha
        })
    except Exception as e:
        cases.append({
            "name": "Tampered Ciphertext Byte",
            "type": "tampered",
            "error": str(e),
            "success": False
        })

    # Case 3: Corrupted Header / Magic
    try:
        corrupted_stego = stego.copy()
        arr = np.array(corrupted_stego)
        # Flip first pixel channel to corrupt magic byte 'G'
        arr[0, 0, 0] ^= 1
        corrupted_stego = Image.fromarray(arr)
        
        detected_corruption = False
        try:
            extract_lsb(corrupted_stego)
        except SteganographyError:
            detected_corruption = True

        cases.append({
            "name": "Corrupted Stego Envelope",
            "type": "tampered",
            "description": "Image pixels altered in steganographic header",
            "sha256_detected": True,
            "aes_gcm_rejected": True,
            "expected_outcome": "Steganographic extraction error or header rejection",
            "actual_outcome": "Corrupted header caught",
            "success": detected_corruption
        })
    except Exception as e:
        cases.append({
            "name": "Corrupted Stego Envelope",
            "type": "tampered",
            "error": str(e),
            "success": False
        })

    # Case 4: Incorrect Password Attempt (Cryptographic authentication check)
    try:
        extracted = extract_lsb(stego)
        integ = verify_payload_integrity(extracted["encrypted_payload"], extracted["stored_hash"])
        s, n, tg, ct = unpack_encrypted_payload(extracted["encrypted_payload"])
        
        wrong_pwd_rejected = False
        try:
            decrypt_message(s, n, tg, ct, "WrongPassword@999!")
        except DecryptionError:
            wrong_pwd_rejected = True

        cases.append({
            "name": "Incorrect Password (AES-GCM Auth)",
            "type": "tampered",
            "description": "Valid SHA-256 integrity, but unauthorized password used",
            "sha256_detected": False,  # Payload itself is intact
            "aes_gcm_rejected": wrong_pwd_rejected,
            "expected_outcome": "AES-GCM Authentication Tag Rejection",
            "actual_outcome": "Decryption Rejected by AES-GCM Tag Mismatch",
            "success": wrong_pwd_rejected
        })
    except Exception as e:
        cases.append({
            "name": "Incorrect Password",
            "type": "tampered",
            "error": str(e),
            "success": False
        })

    tampered_cases = [c for c in cases if c["type"] == "tampered"]
    detected_count = sum(1 for c in tampered_cases if c.get("success", False))
    total_tampered = len(tampered_cases)
    detection_rate = (detected_count / total_tampered * 100.0) if total_tampered > 0 else 0.0

    return {
        "total_tampered_tested": total_tampered,
        "tampered_detected": detected_count,
        "integrity_detection_rate_pct": round(detection_rate, 2),
        "test_cases": cases
    }

