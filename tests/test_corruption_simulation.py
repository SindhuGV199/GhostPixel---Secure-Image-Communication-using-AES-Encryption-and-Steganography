"""
GhostPixel - Corruption Simulation & Receiver Robustness Test Suite
Validates all corruption techniques and receiver verification:
1. Original unmodified stego image (successful recovery)
2. Random pixel modification (both payload-damaging and unused-region safe)
3. JPEG compression (lossy DCT destruction detection)
4. Cropping (top header destruction, right stride shift, bottom untouched)
5. Resizing (bicubic downscaling destruction detection)
6. Payload bit flipping (precision LSB inversion across envelope components)
7. Incorrect password (SHA-256 verified, AES-GCM auth failed)
8. Invalid or unsupported image (graceful format/magic rejection)
9. Flask REST API endpoints (/api/simulate-corruption, /api/inspect-stego)
"""

import io
import unittest
from PIL import Image

from app import app
from backend.encryption import encrypt_message, unpack_encrypted_payload
from backend.hashing import compute_sha256
from backend.steganography import embed_lsb, extract_lsb
from backend.integrity import verify_transmission
from backend.corruption import (
    corrupt_by_bit_flipping,
    corrupt_by_random_pixels,
    corrupt_by_jpeg_compression,
    corrupt_by_cropping,
    corrupt_by_resizing,
    execute_corruption_and_verification,
    inspect_stego_layout
)


class TestCorruptionSimulation(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        cls.client = app.test_client()

        cls.secret_message = "Confidential GhostPixel Test Payload: 2026-CyberSecurity"
        cls.correct_password = "GhostPixel@IntegrityKey2026!"
        cls.wrong_password = "WrongPassword@2026!"

        # Create standard test cover carrier (300x300 RGB)
        cls.cover_img = Image.new("RGB", (300, 300), (35, 45, 55))

        # Encrypt and package payload
        enc = encrypt_message(cls.secret_message, cls.correct_password)
        payload = enc["encrypted_payload"]
        hash_digest = compute_sha256(payload)

        # Embed into carrier to create valid stego image
        cls.stego_img = embed_lsb(cls.cover_img, hash_digest + payload)

    def test_1_original_unmodified_stego_image(self):
        """Test that original unmodified stego image with correct password decrypts successfully."""
        report = verify_transmission(self.stego_img, password=self.correct_password)

        self.assertEqual(report["stage_1_extraction"]["status"], "SUCCESS")
        self.assertEqual(report["stage_2_sha256"]["status"], "VERIFIED")
        self.assertEqual(report["stage_3_aes_gcm"]["status"], "AUTHENTICATED")
        self.assertEqual(report["overall_integrity"]["verdict"], "SECURE_AND_AUTHENTICATED")
        self.assertEqual(report["recovered_message"], self.secret_message)

    def test_2_payload_bit_flipping_tamper_detection(self):
        """Test deliberate LSB bit flipping in ciphertext, tag, and stored hash."""
        # Case A: 1 bit flipped in ciphertext
        res_ct = execute_corruption_and_verification(
            self.stego_img,
            technique="bit_flipping",
            params={"num_flips": 1, "target_part": "ciphertext"},
            password=self.correct_password
        )
        self.assertEqual(res_ct["verification"]["final_result"], "CORRUPTION DETECTED")
        self.assertEqual(res_ct["verification"]["sha256_status"], "MISMATCH")
        self.assertIsNone(res_ct["verification"]["recovered_message"])

        # Case B: 1 bit flipped in 128-bit authentication tag
        res_tag = execute_corruption_and_verification(
            self.stego_img,
            technique="bit_flipping",
            params={"num_flips": 1, "target_part": "tag"},
            password=self.correct_password
        )
        self.assertEqual(res_tag["verification"]["final_result"], "CORRUPTION DETECTED")
        self.assertEqual(res_tag["verification"]["sha256_status"], "MISMATCH")
        self.assertIsNone(res_tag["verification"]["recovered_message"])

        # Case C: 1 bit flipped in stored SHA-256 digest
        res_hash = execute_corruption_and_verification(
            self.stego_img,
            technique="bit_flipping",
            params={"num_flips": 1, "target_part": "stored_hash"},
            password=self.correct_password
        )
        self.assertEqual(res_hash["verification"]["final_result"], "CORRUPTION DETECTED")
        self.assertEqual(res_hash["verification"]["sha256_status"], "MISMATCH")
        self.assertIsNone(res_hash["verification"]["recovered_message"])

    def test_3_random_pixel_modification(self):
        """Test random pixel modification: both honest intact reporting and payload corruption."""
        # Case A: Pixels modified strictly in unused area (payload untouched)
        res_unused = execute_corruption_and_verification(
            self.stego_img,
            technique="random_pixels",
            params={"intensity": 5.0, "target_region": "unused"},
            password=self.correct_password
        )
        self.assertEqual(res_unused["verification"]["final_result"], "SUCCESSFUL")
        self.assertEqual(res_unused["verification"]["sha256_status"], "VERIFIED")
        self.assertEqual(res_unused["verification"]["aes_gcm_status"], "AUTHENTICATED")
        self.assertEqual(res_unused["verification"]["recovered_message"], self.secret_message)

        # Case B: Pixels modified in payload area (corruption guaranteed)
        res_payload = execute_corruption_and_verification(
            self.stego_img,
            technique="random_pixels",
            params={"intensity": 5.0, "target_region": "payload"},
            password=self.correct_password
        )
        self.assertEqual(res_payload["verification"]["final_result"], "CORRUPTION DETECTED")
        self.assertIsNone(res_payload["verification"]["recovered_message"])

    def test_4_jpeg_compression(self):
        """Test JPEG compression at various quality levels destroys LSB integrity."""
        for quality in [75, 50, 30]:
            res = execute_corruption_and_verification(
                self.stego_img,
                technique="jpeg_compression",
                params={"quality": quality},
                password=self.correct_password
            )
            self.assertEqual(res["verification"]["final_result"], "CORRUPTION DETECTED")
            self.assertIn(
                res["verification"]["extraction_status"],
                ["CARRIER_CORRUPTED", "EXTRACTION_FAILED"]
            )
            self.assertIsNone(res["verification"]["recovered_message"])

    def test_5_image_cropping(self):
        """Test image cropping: right edge stride shift, top edge header destruction, and bottom margin."""
        # Case A: Crop right edge (width changes -> row stride shifts -> SHA-256 mismatch)
        res_r = execute_corruption_and_verification(
            self.stego_img,
            technique="cropping",
            params={"percentage": 10.0, "crop_edge": "right"},
            password=self.correct_password
        )
        self.assertEqual(res_r["verification"]["final_result"], "CORRUPTION DETECTED")
        self.assertIsNone(res_r["verification"]["recovered_message"])

        # Case B: Crop top edge (removes row 0 containing 'GPX1' magic signature)
        res_t = execute_corruption_and_verification(
            self.stego_img,
            technique="cropping",
            params={"percentage": 10.0, "crop_edge": "top"},
            password=self.correct_password
        )
        self.assertEqual(res_t["verification"]["final_result"], "CORRUPTION DETECTED")
        self.assertEqual(res_t["verification"]["extraction_status"], "CARRIER_CORRUPTED")
        self.assertIsNone(res_t["verification"]["recovered_message"])

        # Case C: Crop bottom edge on 300x300 image where payload occupies only top ~15 rows
        # 5% bottom crop removes rows 285..299, leaving payload completely untouched!
        res_b = execute_corruption_and_verification(
            self.stego_img,
            technique="cropping",
            params={"percentage": 5.0, "crop_edge": "bottom"},
            password=self.correct_password
        )
        self.assertEqual(res_b["verification"]["final_result"], "SUCCESSFUL")
        self.assertEqual(res_b["verification"]["recovered_message"], self.secret_message)

    def test_6_image_resizing(self):
        """Test image resizing: bicubic downscaling destroys LSB planes."""
        res = execute_corruption_and_verification(
            self.stego_img,
            technique="resizing",
            params={"scale_factor": 0.75},
            password=self.correct_password
        )
        self.assertEqual(res["verification"]["final_result"], "CORRUPTION DETECTED")
        self.assertEqual(res["verification"]["extraction_status"], "CARRIER_CORRUPTED")
        self.assertIsNone(res["verification"]["recovered_message"])

    def test_7_incorrect_password(self):
        """Test that incorrect password fails AES-GCM authentication while SHA-256 passes."""
        report = verify_transmission(self.stego_img, password=self.wrong_password)

        self.assertEqual(report["stage_1_extraction"]["status"], "SUCCESS")
        self.assertEqual(report["stage_2_sha256"]["status"], "VERIFIED")
        self.assertEqual(report["stage_3_aes_gcm"]["status"], "AUTH_FAILED")
        self.assertEqual(report["overall_integrity"]["verdict"], "AUTHENTICATION_FAILED")
        self.assertIsNone(report["recovered_message"])

    def test_8_invalid_or_unsupported_image(self):
        """Test invalid or non-stego images: plain image with no signature rejected gracefully."""
        plain_img = Image.new("RGB", (200, 200), (100, 150, 200))
        report = verify_transmission(plain_img, password=self.correct_password)

        self.assertEqual(report["stage_1_extraction"]["status"], "CARRIER_CORRUPTED")
        self.assertFalse(report["stage_1_extraction"]["magic_verified"])
        self.assertIsNone(report["recovered_message"])

    def test_9_api_simulate_corruption_endpoint(self):
        """Test Flask REST API endpoint /api/simulate-corruption and /api/inspect-stego."""
        # Convert stego image to PNG bytes
        buf = io.BytesIO()
        self.stego_img.save(buf, format="PNG")
        buf.seek(0)

        # 1. Test inspect endpoint
        inspect_resp = self.client.post(
            "/api/inspect-stego",
            data={"image": (io.BytesIO(buf.getvalue()), "stego.png")},
            content_type="multipart/form-data"
        )
        self.assertEqual(inspect_resp.status_code, 200)
        insp_data = inspect_resp.get_json()
        self.assertTrue(insp_data["success"])
        self.assertTrue(insp_data["layout"]["is_valid_stego"])

        # 2. Test simulate corruption endpoint with bit flipping
        sim_resp = self.client.post(
            "/api/simulate-corruption",
            data={
                "stego_image": (io.BytesIO(buf.getvalue()), "stego.png"),
                "technique": "bit_flipping",
                "num_flips": "1",
                "target_part": "ciphertext",
                "password": self.correct_password
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(sim_resp.status_code, 200)
        sim_data = sim_resp.get_json()
        self.assertTrue(sim_data["success"])
        self.assertEqual(sim_data["verification"]["final_result"], "CORRUPTION DETECTED")
        self.assertIn("corrupted_image_url", sim_data)
        self.assertIn("download_url", sim_data)


if __name__ == "__main__":
    unittest.main()
