"""
GhostPixel - Corruption Simulation and Testing Module
Provides controlled simulation of transport-layer, carrier, and payload corruption:
1. Random Pixel Modification (Configurable intensity, entire image, or targeted regions)
2. JPEG Lossy Compression (Configurable quality levels 10-95)
3. Image Cropping (Percentage removal from bottom, right, top, or margins)
4. Image Resizing (Downscaling via bicubic interpolation)
5. Precise Payload Bit Flipping (Exact bit inversion based on GhostPixel binary envelope layout)

All corruption techniques operate on copies of the image; original inputs are never modified.
Cryptographic verification uses the real GhostPixel transmission integrity pipeline.
"""

import io
import time
import math
import struct
from typing import Dict, Any, Tuple, Optional, List
import numpy as np
from PIL import Image

from backend.steganography import (
    MAGIC_BYTES,
    HEADER_SIZE,
    MIN_PAYLOAD_SIZE,
    SteganographyError
)
from backend.integrity import verify_transmission


class CorruptionSimulationError(Exception):
    """Raised when corruption simulation fails or parameters are invalid."""
    pass


def inspect_stego_layout(image: Image.Image) -> Dict[str, Any]:
    """
    Analyzes an RGB image to determine if it carries a valid GhostPixel stego envelope
    and calculates the exact channel offsets of each cryptographic component:
    - Header: MAGIC (4B) + Length (4B) = 64 bits (channels 0..63)
    - Stored SHA-256 Hash: 32B = 256 bits (channels 64..319)
    - Salt: 16B = 128 bits (channels 320..447)
    - Nonce: 12B = 96 bits (channels 448..543)
    - Auth Tag: 16B = 128 bits (channels 544..671)
    - Ciphertext: remaining bytes (channels 672..total_payload_channels-1)
    """
    if image.mode != "RGB":
        image = image.convert("RGB")

    width, height = image.size
    total_channels = width * height * 3

    if total_channels < HEADER_SIZE * 8:
        return {
            "is_valid_stego": False,
            "error": "Image capacity smaller than GhostPixel header."
        }

    arr = np.array(image, dtype=np.uint8)
    flat = arr.reshape(-1)

    # Read 64 header bits
    header_bits = flat[: HEADER_SIZE * 8] & 1
    header_bytes = np.packbits(header_bits).tobytes()

    magic = header_bytes[:4]
    if magic != MAGIC_BYTES:
        return {
            "is_valid_stego": False,
            "error": "No GhostPixel signature ('GPX1') found in carrier header."
        }

    payload_len = struct.unpack(">I", header_bytes[4:8])[0]
    total_payload_bits = payload_len * 8
    total_envelope_bits = (HEADER_SIZE + payload_len) * 8

    if payload_len < MIN_PAYLOAD_SIZE or total_envelope_bits > total_channels:
        return {
            "is_valid_stego": False,
            "error": f"Invalid payload length header: {payload_len} bytes."
        }

    # Offset map in flat channel indices:
    header_start = 0
    header_end = 64
    stored_hash_start = 64
    stored_hash_end = 320
    salt_start = 320
    salt_end = 448
    nonce_start = 448
    nonce_end = 544
    tag_start = 544
    tag_end = 672
    ciphertext_start = 672
    ciphertext_end = total_envelope_bits

    payload_pixels_count = math.ceil(total_envelope_bits / 3)
    total_pixels = width * height
    unused_pixels = max(0, total_pixels - payload_pixels_count)

    return {
        "is_valid_stego": True,
        "width": width,
        "height": height,
        "total_channels": total_channels,
        "total_pixels": total_pixels,
        "payload_len": payload_len,
        "total_envelope_bits": total_envelope_bits,
        "payload_pixels_count": payload_pixels_count,
        "unused_pixels_count": unused_pixels,
        "offsets": {
            "header": (header_start, header_end),
            "stored_hash": (stored_hash_start, stored_hash_end),
            "salt": (salt_start, salt_end),
            "nonce": (nonce_start, nonce_end),
            "tag": (tag_start, tag_end),
            "ciphertext": (ciphertext_start, ciphertext_end),
            "envelope": (0, total_envelope_bits)
        }
    }


def corrupt_by_bit_flipping(
    image: Image.Image,
    num_flips: int = 1,
    target_part: str = "ciphertext",
    specific_bit_offset: Optional[int] = None
) -> Tuple[Image.Image, Dict[str, Any]]:
    """
    Deliberately inverts selected LSB bits in the carrier without modifying any unrelated pixel data.
    Uses exact GhostPixel binary envelope layout:
    - 'ciphertext': Inverts bits in the AES-GCM ciphertext region.
    - 'tag': Inverts bits in the 128-bit authentication tag.
    - 'nonce': Inverts bits in the 96-bit initialization vector.
    - 'salt': Inverts bits in the 128-bit PBKDF2 salt.
    - 'stored_hash': Inverts bits in the 256-bit SHA-256 digest header.
    - 'header_magic': Inverts bits in 'GPX1' magic bytes.
    - 'random_payload': Inverts bits anywhere in the payload envelope.
    """
    layout = inspect_stego_layout(image)
    if not layout.get("is_valid_stego"):
        raise CorruptionSimulationError(
            f"Cannot perform targeted bit flipping: {layout.get('error', 'Invalid stego image')}"
        )

    offsets = layout["offsets"]
    part_key = target_part.lower()

    if part_key in offsets:
        start_idx, end_idx = offsets[part_key]
    elif part_key in ("header_magic", "magic"):
        start_idx, end_idx = (0, 32)
    elif part_key in ("header_length", "length"):
        start_idx, end_idx = (32, 64)
    elif part_key in ("random_payload", "payload"):
        start_idx, end_idx = offsets["stored_hash"][0], offsets["ciphertext"][1]
    else:
        # Default to ciphertext
        start_idx, end_idx = offsets["ciphertext"]

    if start_idx >= end_idx:
        start_idx, end_idx = offsets["stored_hash"]

    available_bits = end_idx - start_idx
    actual_flips = max(1, min(num_flips, available_bits))

    # Deep copy image array to ensure original image is never modified
    arr = np.array(image.convert("RGB"), dtype=np.uint8, copy=True)
    flat = arr.reshape(-1)

    flipped_positions: List[int] = []

    if specific_bit_offset is not None and start_idx <= specific_bit_offset < end_idx:
        target_indices = [specific_bit_offset]
    else:
        # Select evenly spaced or randomized positions in target part
        if actual_flips == 1:
            target_indices = [start_idx]
        else:
            step = max(1, available_bits // actual_flips)
            target_indices = [start_idx + i * step for i in range(actual_flips) if start_idx + i * step < end_idx]

    for bit_pos in target_indices:
        # Flip the least significant bit (XOR with 1)
        flat[bit_pos] ^= 1
        flipped_positions.append(int(bit_pos))

    corrupted_img = Image.fromarray(arr, mode="RGB")

    return corrupted_img, {
        "technique": "Payload Bit Flipping",
        "target_part": target_part,
        "bits_flipped_count": len(flipped_positions),
        "flipped_bit_indices": flipped_positions[:10],  # preview first 10
        "target_range": [start_idx, end_idx],
        "unrelated_pixels_modified": 0
    }


def corrupt_by_random_pixels(
    image: Image.Image,
    intensity_percent: float = 1.0,
    target_region: str = "all",
    seed: Optional[int] = None
) -> Tuple[Image.Image, Dict[str, Any]]:
    """
    Randomly modifies RGB pixel values at configurable intensity levels.
    - 'all': Uniform random selection across entire image.
    - 'payload': Modifies pixels specifically within the hidden payload footprint.
    - 'unused': Modifies pixels strictly in the unused region outside payload footprint.
                (Demonstrates that when payload is untouched, verification succeeds).
    """
    if image.mode != "RGB":
        image = image.convert("RGB")

    width, height = image.size
    total_pixels = width * height
    layout = inspect_stego_layout(image)

    payload_pixels_count = layout.get("payload_pixels_count", 0) if layout.get("is_valid_stego") else 0

    if seed is not None:
        np.random.seed(seed)

    region = target_region.lower()
    if region == "payload" and payload_pixels_count > 0:
        pool = np.arange(0, payload_pixels_count)
    elif region == "unused" and payload_pixels_count > 0 and payload_pixels_count < total_pixels:
        pool = np.arange(payload_pixels_count, total_pixels)
    else:
        # 'all' or fallback
        pool = np.arange(0, total_pixels)
        region = "all"

    if len(pool) == 0:
        pool = np.arange(0, total_pixels)
        region = "all"

    # Calculate number of pixels to corrupt
    fraction = max(0.0001, min(1.0, float(intensity_percent) / 100.0))
    k = max(1, int(len(pool) * fraction))
    chosen_indices = np.random.choice(pool, size=k, replace=False)

    # Deep copy array so original is untouched
    arr = np.array(image, dtype=np.uint8, copy=True)
    flat_pixels = arr.reshape(-1, 3)

    # Add random noise or replace with random values
    noise = np.random.randint(1, 256, size=(k, 3), dtype=np.uint8)
    flat_pixels[chosen_indices] = (flat_pixels[chosen_indices] ^ noise)

    corrupted_img = Image.fromarray(arr, mode="RGB")

    # Evaluate how many affected pixels were in payload region
    if payload_pixels_count > 0:
        payload_pixels_hit = int(np.sum(chosen_indices < payload_pixels_count))
    else:
        payload_pixels_hit = -1

    return corrupted_img, {
        "technique": "Random Pixel Modification",
        "intensity_percent": intensity_percent,
        "target_region": region,
        "pixels_modified": k,
        "total_image_pixels": total_pixels,
        "payload_pixels_hit": payload_pixels_hit,
        "payload_unaffected": (payload_pixels_hit == 0 and payload_pixels_count > 0)
    }


def corrupt_by_jpeg_compression(
    image: Image.Image,
    quality: int = 75
) -> Tuple[Image.Image, Dict[str, Any]]:
    """
    Simulates lossy transport compression by encoding image as JPEG at selectable quality,
    then decoding back to RGB. This destroys high-frequency LSB planes via DCT quantization.
    """
    if image.mode != "RGB":
        image = image.convert("RGB")

    safe_quality = max(5, min(95, int(quality)))

    # Save to memory buffer as JPEG
    buf = io.BytesIO()
    image.save(buf, format="JPEG", quality=safe_quality, optimize=True)
    jpeg_bytes_len = buf.tell()
    buf.seek(0)

    # Re-open as PIL image
    jpeg_img = Image.open(buf)
    # Convert to RGB array to simulate receiving and processing as carrier
    arr = np.array(jpeg_img.convert("RGB"), dtype=np.uint8, copy=True)
    corrupted_img = Image.fromarray(arr, mode="RGB")

    return corrupted_img, {
        "technique": "JPEG Compression",
        "quality": safe_quality,
        "compressed_bytes": jpeg_bytes_len,
        "compression_type": "Lossy DCT (Discrete Cosine Transform)"
    }


def corrupt_by_cropping(
    image: Image.Image,
    percentage: float = 10.0,
    crop_edge: str = "bottom"
) -> Tuple[Image.Image, Dict[str, Any]]:
    """
    Removes a configurable percentage of the carrier image.
    - 'bottom': Truncates rows from the bottom. If payload fits in top portion,
                payload might remain intact!
    - 'right': Truncates columns from the right. Modifies row stride, shifting
               2D pixel coordinates and corrupting payload alignment.
    - 'top': Truncates top rows, instantly destroying magic header 'GPX1'.
    - 'left': Truncates left columns, misaligning all pixels and destroying header.
    """
    if image.mode != "RGB":
        image = image.convert("RGB")

    width, height = image.size
    p = max(1.0, min(80.0, float(percentage))) / 100.0
    edge = crop_edge.lower()

    if edge == "right":
        new_w = max(10, int(width * (1.0 - p)))
        box = (0, 0, new_w, height)
    elif edge == "top":
        new_top = min(height - 10, int(height * p))
        box = (0, new_top, width, height)
    elif edge == "left":
        new_left = min(width - 10, int(width * p))
        box = (new_left, 0, width, height)
    else:
        # Default: 'bottom'
        new_h = max(10, int(height * (1.0 - p)))
        box = (0, 0, width, new_h)
        edge = "bottom"

    cropped = image.crop(box)

    return cropped, {
        "technique": "Image Cropping",
        "crop_edge": edge,
        "percentage_removed": percentage,
        "original_dimensions": [width, height],
        "cropped_dimensions": [cropped.width, cropped.height]
    }


def corrupt_by_resizing(
    image: Image.Image,
    scale_factor: float = 0.75
) -> Tuple[Image.Image, Dict[str, Any]]:
    """
    Downsamples the carrier image to a smaller resolution using bicubic interpolation.
    Interpolation recalculates pixel values, completely destroying LSB states.
    """
    if image.mode != "RGB":
        image = image.convert("RGB")

    width, height = image.size
    factor = max(0.1, min(0.95, float(scale_factor)))

    new_w = max(8, int(width * factor))
    new_h = max(8, int(height * factor))

    resized = image.resize((new_w, new_h), resample=Image.Resampling.BICUBIC)

    return resized, {
        "technique": "Image Resizing",
        "scale_factor": factor,
        "interpolation": "Bicubic",
        "original_dimensions": [width, height],
        "resized_dimensions": [new_w, new_h]
    }


def execute_corruption_and_verification(
    image: Image.Image,
    technique: str,
    params: Dict[str, Any],
    password: Optional[str] = None
) -> Dict[str, Any]:
    """
    Master pipeline:
    1. Executes the requested corruption technique on a separate copy of the image.
    2. Runs the exact, real-world GhostPixel transmission integrity verification engine
       (backend.integrity.verify_transmission) on the corrupted image.
    3. Guarantees:
       - Original image is never mutated.
       - No partial or unverified plaintext is returned if verification fails.
       - Honest reporting: modifications that do not affect the payload are reported as intact.
    """
    t_start = time.perf_counter()

    technique_clean = technique.lower().replace("-", "_").replace(" ", "_")

    if technique_clean in ("bit_flipping", "payload_bit_flipping"):
        num_flips = int(params.get("num_flips", 1))
        target_part = str(params.get("target_part", "ciphertext"))
        corrupted_img, corr_meta = corrupt_by_bit_flipping(image, num_flips=num_flips, target_part=target_part)

    elif technique_clean in ("random_pixels", "pixel_modification", "random_pixel_modification"):
        intensity = float(params.get("intensity", 1.0))
        target_region = str(params.get("target_region", "all"))
        corrupted_img, corr_meta = corrupt_by_random_pixels(image, intensity_percent=intensity, target_region=target_region)

    elif technique_clean in ("jpeg_compression", "jpeg"):
        quality = int(params.get("quality", 75))
        corrupted_img, corr_meta = corrupt_by_jpeg_compression(image, quality=quality)

    elif technique_clean in ("cropping", "image_cropping"):
        percentage = float(params.get("percentage", 15.0))
        crop_edge = str(params.get("crop_edge", "bottom"))
        corrupted_img, corr_meta = corrupt_by_cropping(image, percentage=percentage, crop_edge=crop_edge)

    elif technique_clean in ("resizing", "image_resizing"):
        scale_factor = float(params.get("scale_factor", 0.75))
        corrupted_img, corr_meta = corrupt_by_resizing(image, scale_factor=scale_factor)

    else:
        raise CorruptionSimulationError(f"Unknown corruption technique: '{technique}'")

    # Step 2: Run authentic Receiver Transmission Integrity Verification
    verif_report = verify_transmission(corrupted_img, password=password)
    t_elapsed_ms = (time.perf_counter() - t_start) * 1000.0

    # Determine final result strictly based on verification report
    st1 = verif_report["stage_1_extraction"]["status"]
    st2 = verif_report["stage_2_sha256"]["status"]
    st3 = verif_report["stage_3_aes_gcm"]["status"]
    overall = verif_report["overall_integrity"]["verdict"]

    extraction_succeeded = (st1 == "SUCCESS")
    sha256_succeeded = (st2 == "VERIFIED")
    aes_gcm_succeeded = (st3 == "AUTHENTICATED")

    if password:
        if aes_gcm_succeeded:
            final_result = "SUCCESSFUL"
        else:
            final_result = "CORRUPTION DETECTED"
    else:
        # If no password supplied, check if carrier extraction and SHA-256 passed
        if extraction_succeeded and sha256_succeeded:
            final_result = "SUCCESSFUL"
        else:
            final_result = "CORRUPTION DETECTED"

    return {
        "technique": corr_meta["technique"],
        "technique_key": technique_clean,
        "original_dimensions": f"{image.width}x{image.height}",
        "corrupted_dimensions": f"{corrupted_img.width}x{corrupted_img.height}",
        "corruption_metadata": corr_meta,
        "verification": {
            "extraction_succeeded": extraction_succeeded,
            "extraction_status": st1,
            "extraction_details": verif_report["stage_1_extraction"]["details"],
            "sha256_succeeded": sha256_succeeded,
            "sha256_status": st2,
            "calculated_hash": verif_report["stage_2_sha256"]["calculated_hash"],
            "stored_hash": verif_report["stage_2_sha256"]["stored_hash"],
            "aes_gcm_succeeded": aes_gcm_succeeded,
            "aes_gcm_status": st3,
            "overall_verdict": overall,
            "final_result": final_result,
            "diagnostic_recommendation": verif_report["overall_integrity"]["diagnostic_recommendation"],
            # Plaintext is ONLY provided if AES-GCM tag verification succeeded
            "recovered_message": verif_report.get("recovered_message") if aes_gcm_succeeded else None
        },
        "corrupted_image": corrupted_img,
        "processing_time_ms": round(t_elapsed_ms, 2)
    }
