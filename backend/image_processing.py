"""
GhostPixel - Image Processing Module
Handles image loading, format validation, capacity checking, and saving in lossless PNG format.
"""

import io
import os
from typing import Tuple, Dict, Any, Union
from PIL import Image, UnidentifiedImageError

SUPPORTED_FORMATS = {"PNG", "BMP"}
HEADER_RESERVED_BYTES = 8  # 4 bytes magic "GPX1" + 4 bytes payload length


class ImageProcessingError(Exception):
    """Raised when image processing or validation fails."""
    pass


class InsufficientCapacityError(Exception):
    """Raised when the cover image is too small to embed the encrypted payload."""
    pass


def load_image(source: Union[str, bytes, io.BytesIO]) -> Tuple[Image.Image, str]:
    """
    Loads an image from a file path, bytes, or BytesIO object.
    Validates format (PNG or BMP) and converts to RGB mode.
    Returns: (PIL.Image, detected_format)
    """
    try:
        if isinstance(source, (str, os.PathLike)):
            img = Image.open(source)
        elif isinstance(source, (bytes, bytearray)):
            img = Image.open(io.BytesIO(source))
        elif isinstance(source, io.BytesIO):
            img = Image.open(source)
        else:
            raise ImageProcessingError("Invalid image source type.")

        img_format = (img.format or "").upper()
        if img_format not in SUPPORTED_FORMATS:
            raise ImageProcessingError(
                f"Unsupported image format: '{img_format or 'UNKNOWN'}'. "
                f"GhostPixel strictly requires lossless formats ({', '.join(sorted(SUPPORTED_FORMATS))}) "
                f"to prevent lossy compression from destroying hidden LSB data."
            )

        # Convert to RGB mode to guarantee exactly 3 channels (R, G, B)
        if img.mode != "RGB":
            if img.mode == "RGBA":
                # Composite over pure white background to avoid alpha distortion
                background = Image.new("RGB", img.size, (255, 255, 255))
                background.paste(img, mask=img.split()[3])
                img = background
            else:
                img = img.convert("RGB")

        # Force load pixel data into memory
        img.load()
        return img, img_format

    except UnidentifiedImageError:
        raise ImageProcessingError("The provided file is not a valid or readable image.")
    except ImageProcessingError:
        raise
    except Exception as e:
        raise ImageProcessingError(f"Error loading image: {str(e)}")


def calculate_image_capacity(width: int, height: int, channels: int = 3) -> Dict[str, Any]:
    """
    Calculates the theoretical and usable capacity for an RGB image using 1 LSB per channel.
    Formula: Usable Capacity in Bytes = (Width * Height * Channels) // 8
    """
    if width <= 0 or height <= 0:
        raise ImageProcessingError("Image dimensions must be positive integers.")

    total_pixels = width * height
    total_bits = total_pixels * channels
    usable_bytes = total_bits // 8

    return {
        "width": width,
        "height": height,
        "channels": channels,
        "total_pixels": total_pixels,
        "total_bits": total_bits,
        "usable_capacity_bytes": usable_bytes,
        "usable_capacity_kb": round(usable_bytes / 1024, 2),
        "usable_capacity_mb": round(usable_bytes / (1024 * 1024), 2)
    }


def evaluate_capacity_for_payload(
    image: Image.Image,
    required_payload_size: int
) -> Dict[str, Any]:
    """
    Evaluates whether the given image has sufficient capacity to embed the required payload.
    Includes the 8-byte header (magic + length) in the total required bytes.
    """
    width, height = image.size
    cap_info = calculate_image_capacity(width, height, 3)
    usable_bytes = cap_info["usable_capacity_bytes"]
    
    # Total required bytes includes the steganographic envelope (Magic + Length + Data)
    total_required = required_payload_size + HEADER_RESERVED_BYTES
    available_bytes = usable_bytes - total_required
    has_capacity = available_bytes >= 0

    utilization_pct = min(100.0, round((total_required / usable_bytes) * 100, 3)) if usable_bytes > 0 else 100.0

    return {
        "has_capacity": has_capacity,
        "width": width,
        "height": height,
        "total_usable_bytes": usable_bytes,
        "payload_bytes": required_payload_size,
        "header_bytes": HEADER_RESERVED_BYTES,
        "total_required_bytes": total_required,
        "available_bytes": max(0, available_bytes),
        "utilization_pct": utilization_pct,
        "formatted_usable": f"{usable_bytes:,} bytes ({round(usable_bytes/1024, 1)} KB)",
        "formatted_required": f"{total_required:,} bytes ({round(total_required/1024, 1)} KB)",
        "formatted_available": f"{max(0, available_bytes):,} bytes"
    }


def save_image_as_png(image: Image.Image, target_path: str) -> str:
    """
    Saves the image strictly as lossless PNG to preserve embedded LSB bits.
    """
    os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
    image.save(target_path, format="PNG", optimize=False)
    return target_path


def generate_difference_map(
    cover_image: Image.Image,
    stego_image: Image.Image,
    amplification: int = 200
) -> Image.Image:
    """
    Generates a visual difference map between the cover carrier and the stego image.
    Amplifies 1-bit discrepancies (0 or 1) by `amplification` so the altered pixel
    locations become clearly visible against a dark background for steganalysis inspection.
    """
    if cover_image.size != stego_image.size:
        raise ImageProcessingError("Images must have identical dimensions to compute difference map.")

    import numpy as np
    c_arr = np.array(cover_image.convert("RGB"), dtype=np.int16)
    s_arr = np.array(stego_image.convert("RGB"), dtype=np.int16)

    diff = np.abs(c_arr - s_arr) * amplification
    diff_clipped = np.clip(diff, 0, 255).astype(np.uint8)

    return Image.fromarray(diff_clipped, mode="RGB")


def extract_bit_plane(image: Image.Image, bit: int = 0, channel: int = 0) -> Image.Image:
    """
    Extracts a specific bit plane (default bit 0 = LSB) of a given channel (0=R, 1=G, 2=B).
    Expands 0/1 bits to 0/255 for high-contrast grayscale visualization.
    """
    import numpy as np
    arr = np.array(image.convert("RGB"), dtype=np.uint8)
    plane = ((arr[:, :, channel] >> bit) & 1) * 255
    return Image.fromarray(plane.astype(np.uint8), mode="L")


def image_to_bytes(image: Image.Image) -> bytes:
    """
    Converts a PIL Image to PNG bytes in memory.
    """
    buffer = io.BytesIO()
    image.save(buffer, format="PNG", optimize=False)
    return buffer.getvalue()

