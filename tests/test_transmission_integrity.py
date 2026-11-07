"""
Comprehensive Automated Tests for GhostPixel Transmission Integrity Verification Module.
Validates:
1. SHA-256 payload digest verification before decryption.
2. AES-256-GCM cryptographic authentication tag verification.
3. Hidden payload bit modification detection.
4. Lossy JPEG compression resilience / detection.
5. Image resizing detection.
6. Image cropping detection.
7. Corrupted image data and malformed envelope headers.
8. Strict diagnostic distinction between data corruption, wrong password, and unsupported formats.
9. Guarantee that partial plaintext is never exposed upon failure.
"""

import unittest
import io
import json
import numpy as np
from PIL import Image

from app import app, init_db
from backend.encryption import encrypt_message, decrypt_message, unpack_encrypted_payload
from backend.hashing import compute_sha256, verify_sha256
from backend.steganography import embed_lsb, extract_lsb, MAGIC_BYTES
from backend.integrity import (
    verify_transmission,
    inspect_image_source,
    CarrierCorruptionError,
    PayloadIntegrityError,
    AuthenticationFailureError,
    FormatUnsupportedError
)


class TestTransmissionIntegrity(unittest.TestCase):

    def setUp(self):
        init_db()
        self.client = app.test_client()
        self.password = "TopSecretIntegrityKey@2026!"
        self.message = (
            "TRANSMISSION VERIFICATION PAYLOAD:\n"
            "Integrity Protocol 2.0 active.\n"
            "Coordinates: 51.5074° N, 0.1278° W.\n"
            "Unicode symbols: 🛡️ 🔐 🕵️ 🚀 🔒 零一二三"
        )

        # Create standard cover carrier image (250x250 RGB PNG)
        arr = np.random.randint(60, 200, (250, 250, 3), dtype=np.uint8)
        self.cover_img = Image.fromarray(arr, mode="RGB")
        buf = io.BytesIO()
        self.cover_img.save(buf, format="PNG")
        self.cover_bytes = buf.getvalue()

        # Generate legitimate stego carrier
        enc = encrypt_message(self.message, self.password)
        raw_payload = enc["encrypted_payload"]
        p_hash = compute_sha256(raw_payload)
        envelope = p_hash + raw_payload

        self.stego_img = embed_lsb(self.cover_img, envelope)
        stego_buf = io.BytesIO()
        self.stego_img.save(stego_buf, format="PNG")
        self.stego_bytes = stego_buf.getvalue()

    def test_1_intact_transmission_verification(self):
        """Validates that a legitimate, unaltered transmission passes all 4 stages."""
        report = verify_transmission(self.stego_bytes, password=self.password)

        # Stage 1: Extraction
        self.assertEqual(report["stage_1_extraction"]["status"], "SUCCESS")
        self.assertTrue(report["stage_1_extraction"]["magic_verified"])

        # Stage 2: SHA-256
        self.assertEqual(report["stage_2_sha256"]["status"], "VERIFIED")
        self.assertTrue(report["stage_2_sha256"]["hash_match"])
        self.assertEqual(
            report["stage_2_sha256"]["calculated_hash"],
            report["stage_2_sha256"]["stored_hash"]
        )

        # Stage 3: AES-GCM
        self.assertEqual(report["stage_3_aes_gcm"]["status"], "AUTHENTICATED")
        self.assertTrue(report["stage_3_aes_gcm"]["tag_verified"])

        # Stage 4: Overall Verdict
        self.assertEqual(report["overall_integrity"]["verdict"], "SECURE_AND_AUTHENTICATED")
        self.assertTrue(report["overall_integrity"]["is_secure"])
        self.assertEqual(report["recovered_message"], self.message)

    def test_2_payload_bit_modification_detection(self):
        """
        Requirement 12: Modify hidden payload bits and verify that the system
        detects the modification via SHA-256 and halts decryption.
        """
        arr = np.array(self.stego_img)
        flat = arr.reshape(-1)

        # Payload starts after 8-byte header (64 bits) + 32-byte hash (256 bits) = channel 320 onwards
        # Flip a bit in the encrypted payload area
        flat[350] ^= 1
        tampered_img = Image.fromarray(flat.reshape(arr.shape))
        buf = io.BytesIO()
        tampered_img.save(buf, format="PNG")
        tampered_bytes = buf.getvalue()

        report = verify_transmission(tampered_bytes, password=self.password)

        # Stage 1 should pass (header format intact)
        self.assertEqual(report["stage_1_extraction"]["status"], "SUCCESS")

        # Stage 2 must catch the single bit flip
        self.assertEqual(report["stage_2_sha256"]["status"], "MISMATCH")
        self.assertFalse(report["stage_2_sha256"]["hash_match"])
        self.assertNotEqual(
            report["stage_2_sha256"]["calculated_hash"],
            report["stage_2_sha256"]["stored_hash"]
        )

        # Stage 3 must be halted
        self.assertEqual(report["stage_3_aes_gcm"]["status"], "HALTED_BY_SHA256_MISMATCH")

        # Overall verdict must report corruption
        self.assertEqual(report["overall_integrity"]["verdict"], "TRANSMISSION_CORRUPTED")
        self.assertEqual(report["overall_integrity"]["code"], "ERR_SHA256_MISMATCH")

        # Plaintext must NEVER be exposed
        self.assertIsNone(report["recovered_message"])

    def test_3_jpeg_compression_detection(self):
        """
        Requirement 13: Simulate saving the stego image as a lossy JPEG.
        Verify system detects JPEG format or destroyed LSB bits.
        """
        # Case A: Saved and uploaded as JPEG
        jpeg_buf = io.BytesIO()
        self.stego_img.save(jpeg_buf, format="JPEG", quality=90)
        jpeg_bytes = jpeg_buf.getvalue()

        report_jpeg = verify_transmission(jpeg_bytes, password=self.password)
        self.assertEqual(report_jpeg["stage_1_extraction"]["status"], "UNSUPPORTED_FORMAT")
        self.assertEqual(report_jpeg["overall_integrity"]["code"], "ERR_FORMAT_JPEG")
        self.assertIsNone(report_jpeg["recovered_message"])

        # Case B: JPEG re-saved as PNG (simulating a platform converting JPEG back to PNG)
        jpeg_reopened = Image.open(io.BytesIO(jpeg_bytes)).convert("RGB")
        re_png_buf = io.BytesIO()
        jpeg_reopened.save(re_png_buf, format="PNG")
        re_png_bytes = re_png_buf.getvalue()

        report_re_png = verify_transmission(re_png_bytes, password=self.password)
        # The LSB bits were destroyed by DCT quantization, so magic GPX1 is destroyed
        self.assertIn(
            report_re_png["stage_1_extraction"]["status"],
            ("CARRIER_CORRUPTED", "EXTRACTION_FAILED")
        )
        self.assertFalse(report_re_png["stage_1_extraction"]["magic_verified"])
        self.assertIsNone(report_re_png["recovered_message"])

    def test_4_image_resizing_detection(self):
        """
        Requirement 13: Resize stego image and verify extraction failure or corruption is caught.
        """
        # Resize image down to 80%
        w, h = self.stego_img.size
        resized_img = self.stego_img.resize((int(w * 0.8), int(h * 0.8)), Image.Resampling.BILINEAR)
        buf = io.BytesIO()
        resized_img.save(buf, format="PNG")
        resized_bytes = buf.getvalue()

        report = verify_transmission(resized_bytes, password=self.password)
        # Interpolation destroys LSBs
        self.assertEqual(report["stage_1_extraction"]["status"], "CARRIER_CORRUPTED")
        self.assertFalse(report["stage_1_extraction"]["magic_verified"])
        self.assertIsNone(report["recovered_message"])

    def test_5_image_cropping_detection(self):
        """
        Requirement 13: Crop stego image and verify truncated carrier or misalignment is caught.
        """
        # Case A: Width crop (shifts row strides, scrambling multi-row payload)
        cropped_img = self.stego_img.crop((0, 0, 210, 210))
        buf = io.BytesIO()
        cropped_img.save(buf, format="PNG")
        cropped_bytes = buf.getvalue()

        report_crop_a = verify_transmission(cropped_bytes, password=self.password)
        # The shifted pixel channels cause extracted payload to differ, failing SHA-256
        self.assertEqual(report_crop_a["stage_2_sha256"]["status"], "MISMATCH")
        self.assertEqual(report_crop_a["overall_integrity"]["verdict"], "TRANSMISSION_CORRUPTED")
        self.assertIsNone(report_crop_a["recovered_message"])

        # Case B: Severe crop (carrier becomes smaller than payload size)
        tiny_crop = self.stego_img.crop((0, 0, 25, 25))
        tiny_buf = io.BytesIO()
        tiny_crop.save(tiny_buf, format="PNG")
        report_crop_b = verify_transmission(tiny_buf.getvalue(), password=self.password)
        self.assertEqual(report_crop_b["stage_1_extraction"]["status"], "CARRIER_CORRUPTED")
        self.assertIsNone(report_crop_b["recovered_message"])

    def test_6_corrupted_header_detection(self):
        """
        Requirement 8 & 13: Corrupt magic bytes or length field and verify detection.
        """
        arr = np.array(self.stego_img)
        flat = arr.reshape(-1)

        # Corrupt bit 0 of magic byte 'G' (first channel)
        flat[0] ^= 1
        tampered_magic_img = Image.fromarray(flat.reshape(arr.shape))
        buf = io.BytesIO()
        tampered_magic_img.save(buf, format="PNG")
        tampered_magic_bytes = buf.getvalue()

        report = verify_transmission(tampered_magic_bytes, password=self.password)
        self.assertEqual(report["stage_1_extraction"]["status"], "CARRIER_CORRUPTED")
        self.assertEqual(report["overall_integrity"]["code"], "ERR_MAGIC_NOT_FOUND")
        self.assertFalse(report["stage_1_extraction"]["magic_verified"])

    def test_7_distinguish_wrong_password_from_data_corruption(self):
        """
        Requirement 9: System must clearly distinguish between data corruption
        (SHA-256 failure) and incorrect password (AES-GCM authentication failure).
        """
        # Case A: Untouched carrier + Incorrect Password
        report_wrong_pwd = verify_transmission(self.stego_bytes, password="WrongPassphrase#999!")
        # SHA-256 MUST pass (data is intact)
        self.assertEqual(report_wrong_pwd["stage_2_sha256"]["status"], "VERIFIED")
        self.assertTrue(report_wrong_pwd["stage_2_sha256"]["hash_match"])
        # AES-GCM MUST fail
        self.assertEqual(report_wrong_pwd["stage_3_aes_gcm"]["status"], "AUTH_FAILED")
        self.assertFalse(report_wrong_pwd["stage_3_aes_gcm"]["tag_verified"])
        self.assertEqual(report_wrong_pwd["overall_integrity"]["code"], "ERR_AES_GCM_AUTH_FAILED")
        self.assertEqual(report_wrong_pwd["overall_integrity"]["verdict"], "AUTHENTICATION_FAILED")

        # Case B: Corrupted carrier + Correct Password
        arr = np.array(self.stego_img)
        flat = arr.reshape(-1)
        flat[400] ^= 1  # corrupt payload
        corrupted_bytes = io.BytesIO()
        Image.fromarray(flat.reshape(arr.shape)).save(corrupted_bytes, format="PNG")

        report_corrupt = verify_transmission(corrupted_bytes.getvalue(), password=self.password)
        # SHA-256 MUST fail
        self.assertEqual(report_corrupt["stage_2_sha256"]["status"], "MISMATCH")
        # AES-GCM was never attempted
        self.assertEqual(report_corrupt["stage_3_aes_gcm"]["status"], "HALTED_BY_SHA256_MISMATCH")
        self.assertEqual(report_corrupt["overall_integrity"]["code"], "ERR_SHA256_MISMATCH")
        self.assertEqual(report_corrupt["overall_integrity"]["verdict"], "TRANSMISSION_CORRUPTED")

    def test_8_api_transmission_integrity_endpoint(self):
        """Tests the REST endpoint /api/verify-integrity."""
        res = self.client.post(
            "/api/verify-integrity",
            data={
                "image": (io.BytesIO(self.stego_bytes), "stego.png"),
                "password": self.password
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertTrue(data["success"])
        rep = data["report"]
        self.assertEqual(rep["overall_integrity"]["verdict"], "SECURE_AND_AUTHENTICATED")
        self.assertEqual(rep["recovered_message"], self.message)


if __name__ == "__main__":
    unittest.main()
