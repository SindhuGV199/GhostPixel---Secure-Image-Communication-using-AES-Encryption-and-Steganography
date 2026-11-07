"""
Tests for LSB Steganography and Image Capacity Evaluation.
"""

import unittest
import numpy as np
from PIL import Image

from backend.steganography import (
    embed_lsb,
    extract_lsb,
    SteganographyError,
    MAGIC_BYTES,
    HEADER_SIZE
)
from backend.image_processing import (
    calculate_image_capacity,
    evaluate_capacity_for_payload,
    InsufficientCapacityError,
    load_image
)


class TestSteganography(unittest.TestCase):

    def setUp(self):
        # Create a sample RGB test image 120x120 pixels
        # Capacity = (120 * 120 * 3) // 8 = 5,400 bytes
        self.width = 120
        self.height = 120
        arr = np.random.randint(50, 200, (self.height, self.width, 3), dtype=np.uint8)
        self.cover_image = Image.fromarray(arr, mode="RGB")

        # Sample payload: 32 bytes hash + 16 bytes salt + 12 bytes nonce + 16 bytes tag + 30 bytes ciphertext = 106 bytes
        self.payload = b"H" * 32 + b"S" * 16 + b"N" * 12 + b"T" * 16 + b"SecretCiphertextData_123456789"

    def test_capacity_calculation(self):
        cap = calculate_image_capacity(100, 100, 3)
        self.assertEqual(cap["usable_capacity_bytes"], (100 * 100 * 3) // 8)  # 3750 bytes

        eval_cap = evaluate_capacity_for_payload(self.cover_image, len(self.payload))
        self.assertTrue(eval_cap["has_capacity"])
        self.assertEqual(eval_cap["total_usable_bytes"], 5400)
        self.assertEqual(eval_cap["total_required_bytes"], len(self.payload) + HEADER_SIZE)

    def test_embed_and_extract_roundtrip(self):
        stego_img = embed_lsb(self.cover_image, self.payload)
        self.assertEqual(stego_img.size, self.cover_image.size)
        self.assertEqual(stego_img.mode, "RGB")

        extracted = extract_lsb(stego_img)
        self.assertEqual(extracted["payload_length"], len(self.payload))
        reconstructed = extracted["stored_hash"] + extracted["encrypted_payload"]
        self.assertEqual(reconstructed, self.payload)
        self.assertEqual(extracted["stored_hash"], self.payload[:32])
        self.assertEqual(extracted["encrypted_payload"], self.payload[32:])

    def test_insufficient_capacity_rejection(self):
        # 10x10 image: capacity is (10 * 10 * 3) // 8 = 37 bytes
        tiny_img = Image.new("RGB", (10, 10), color=(100, 100, 100))
        with self.assertRaises(InsufficientCapacityError):
            embed_lsb(tiny_img, self.payload)

    def test_non_stego_image_rejection(self):
        # A clean image has no GPX1 header
        clean_img = Image.new("RGB", (100, 100), color=(50, 50, 50))
        with self.assertRaises(SteganographyError):
            extract_lsb(clean_img)

    def test_corrupted_header_length_rejection(self):
        stego_img = embed_lsb(self.cover_image, self.payload)
        arr = np.array(stego_img)
        # Flip bits in the length field (bytes 4-7 = bits 32-63)
        flat = arr.reshape(-1)
        flat[35] ^= 1  # Corrupt bit in length header
        corrupted_img = Image.fromarray(arr)

        with self.assertRaises(SteganographyError):
            extract_lsb(corrupted_img)


if __name__ == "__main__":
    unittest.main()

