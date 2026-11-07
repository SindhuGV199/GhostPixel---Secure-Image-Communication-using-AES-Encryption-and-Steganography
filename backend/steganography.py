"""
GhostPixel - Steganography Module
Implements LSB (Least Significant Bit) steganography for embedding and extracting
structured encrypted payloads into RGB image pixel channels.
"""

import struct
from typing import Dict, Any, Tuple
import numpy as np
from PIL import Image

from backend.image_processing import (
    evaluate_capacity_for_payload,
    calculate_image_capacity,
    InsufficientCapacityError
)

MAGIC_BYTES = b"GPX1"  # 4-byte signature to identify GhostPixel stego images
HEADER_SIZE = 8       # 4 bytes MAGIC + 4 bytes PAYLOAD_LENGTH (uint32)
MIN_PAYLOAD_SIZE = 32 + 16 + 12 + 16  # Hash (32) + Salt (16) + Nonce (12) + Tag (16) = 76 bytes


class SteganographyError(Exception):
    """Raised when steganographic encoding or extraction fails."""
    pass


def embed_lsb(cover_image: Image.Image, payload: bytes) -> Image.Image:
    """
    Embeds a structured binary payload into the LSBs of the RGB cover image.
    Uses strict row-by-row, column-by-column, channel (R->G->B) sequential order.
    
    Packet structure:
    [MAGIC: 4 bytes] + [DATA_LEN: 4 bytes] + [PAYLOAD: N bytes]
    """
    if cover_image.mode != "RGB":
        cover_image = cover_image.convert("RGB")

    width, height = cover_image.size
    capacity_check = evaluate_capacity_for_payload(cover_image, len(payload))

    if not capacity_check["has_capacity"]:
        raise InsufficientCapacityError(
            f"Image capacity exceeded. Cover image can store {capacity_check['total_usable_bytes']:,} bytes, "
            f"but payload requires {capacity_check['total_required_bytes']:,} bytes "
            f"({len(payload):,} bytes data + {HEADER_SIZE} bytes header). "
            f"Please choose a larger image or enter a shorter message."
        )

    # Construct the complete binary envelope
    header = MAGIC_BYTES + struct.pack(">I", len(payload))
    envelope = header + payload

    # Convert binary envelope to an array of individual bits (0 or 1)
    bits = np.unpackbits(np.frombuffer(envelope, dtype=np.uint8))
    num_bits = len(bits)

    # Convert image to numpy array of shape (height, width, 3)
    img_array = np.array(cover_image, dtype=np.uint8)
    flat_channels = img_array.reshape(-1)

    # Embed bits into least significant bit of each color channel:
    # Clear LSB using bitwise AND with 0xFE (11111110), then set with payload bit
    flat_channels[:num_bits] = (flat_channels[:num_bits] & 0xFE) | bits

    # Reshape back to image dimensions and instantiate new PIL image
    stego_array = flat_channels.reshape(height, width, 3)
    return Image.fromarray(stego_array, mode="RGB")


def extract_lsb(stego_image: Image.Image) -> Dict[str, Any]:
    """
    Extracts the hidden binary payload from the LSBs of an RGB stego image.
    Reconstructs the header, verifies magic bytes, and extracts the encrypted payload and stored SHA-256 hash.
    """
    if stego_image.mode != "RGB":
        stego_image = stego_image.convert("RGB")

    width, height = stego_image.size
    cap_info = calculate_image_capacity(width, height, 3)
    total_usable_bytes = cap_info["usable_capacity_bytes"]

    # Minimum capacity needed for just the 8-byte header
    if total_usable_bytes < HEADER_SIZE:
        raise SteganographyError("Image dimensions are too small to contain a GhostPixel header.")

    img_array = np.array(stego_image, dtype=np.uint8)
    flat_channels = img_array.reshape(-1)

    # Step 1: Read the 64 bits (8 bytes) of header
    header_bits = flat_channels[: HEADER_SIZE * 8] & 1
    header_bytes = np.packbits(header_bits).tobytes()

    magic = header_bytes[:4]
    if magic != MAGIC_BYTES:
        raise SteganographyError(
            "No GhostPixel signature found in this image. "
            "Either this image does not contain hidden data, or it was saved/compressed with lossy compression (such as JPEG), "
            "which destroyed the least significant bits."
        )

    # Read the 4-byte payload length
    payload_len = struct.unpack(">I", header_bytes[4:8])[0]

    # Validate payload length against image capacity and minimum expected size
    max_allowable_payload = total_usable_bytes - HEADER_SIZE
    if payload_len < MIN_PAYLOAD_SIZE or payload_len > max_allowable_payload:
        raise SteganographyError(
            f"Extracted payload length header ({payload_len:,} bytes) is invalid or corrupted. "
            f"Expected between {MIN_PAYLOAD_SIZE} and {max_allowable_payload:,} bytes."
        )

    # Step 2: Extract the exact payload bits
    total_bits_to_extract = (HEADER_SIZE + payload_len) * 8
    payload_bits = flat_channels[HEADER_SIZE * 8 : total_bits_to_extract] & 1
    payload_bytes = np.packbits(payload_bits).tobytes()

    if len(payload_bytes) != payload_len:
        raise SteganographyError(
            f"Extraction truncated: read {len(payload_bytes)} bytes, expected {payload_len} bytes."
        )

    # The payload is structured as:
    # [STORED_SHA256: 32 bytes] + [ENCRYPTED_PAYLOAD: (payload_len - 32) bytes]
    stored_hash = payload_bytes[:32]
    encrypted_payload = payload_bytes[32:]

    return {
        "stored_hash": stored_hash,
        "stored_hash_hex": stored_hash.hex(),
        "encrypted_payload": encrypted_payload,
        "payload_length": payload_len,
        "encrypted_payload_length": len(encrypted_payload)
    }

