"""
Comprehensive End-to-End Integration Test for GhostPixel
Validates all requirements from Section 15:
- Capacity check
- AES-256-GCM encryption & SHA-256 hash generation
- LSB embedding & Stego PNG generation
- LSB extraction & SHA-256 integrity verification
- Exact message recovery with correct password
- Incorrect password rejection (AES-GCM authentication failure)
- Tampered payload detection (SHA-256 mismatch rejection)
- Full benchmark execution & statistics logging
"""

import unittest
import io
import json
import numpy as np
from PIL import Image
from app import app, init_db


class TestGhostPixelEndToEnd(unittest.TestCase):

    def setUp(self):
        init_db()
        self.client = app.test_client()
        self.password = "TopSecret@GhostPixel2026!"
        self.message = (
            "CONFIDENTIAL DIRECTIVE:\n"
            "Deploy agent to sector 7-G. Rendezvous at 0400 hours.\n"
            "Coordinates: (37.7749° N, 122.4194° W)\n"
            "Special: !@#$%^&*()_+ 🛡️ 🔐 🕵️ 🚀"
        )
        
        # Create a test cover image (300x300 RGB PNG)
        arr = np.random.randint(50, 200, (300, 300, 3), dtype=np.uint8)
        img = Image.fromarray(arr, mode="RGB")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        self.cover_bytes = buf.getvalue()

    def test_end_to_end_flow(self):
        # 1. Check Capacity API
        cap_res = self.client.post(
            "/api/check-capacity",
            data={
                "image": (io.BytesIO(self.cover_bytes), "test_cover.png"),
                "message": self.message
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(cap_res.status_code, 200)
        cap_data = json.loads(cap_res.data)
        self.assertTrue(cap_data["success"])
        self.assertTrue(cap_data["capacity"]["has_capacity"])
        self.assertGreater(cap_data["capacity"]["total_usable_bytes"], 1000)

        # 2. Encode API
        encode_res = self.client.post(
            "/api/encode",
            data={
                "image": (io.BytesIO(self.cover_bytes), "test_cover.png"),
                "message": self.message,
                "password": self.password
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(encode_res.status_code, 200)
        enc_data = json.loads(encode_res.data)
        self.assertTrue(enc_data["success"])
        self.assertIn("download_url", enc_data)
        self.assertGreater(enc_data["metrics"]["psnr"]["psnr_db"], 50.0)
        self.assertGreater(enc_data["metrics"]["ssim"]["ssim"], 0.999)

        # Download the generated stego PNG
        stego_filename = enc_data["filename"]
        dl_res = self.client.get(f"/download/stego/{stego_filename}")
        self.assertEqual(dl_res.status_code, 200)
        stego_bytes = dl_res.data
        dl_res.close()

        # 3. Extract & Verify Integrity API
        extract_res = self.client.post(
            "/api/extract-info",
            data={
                "image": (io.BytesIO(stego_bytes), "stego.png")
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(extract_res.status_code, 200)
        extract_data = json.loads(extract_res.data)
        self.assertTrue(extract_data["success"])
        self.assertTrue(extract_data["integrity"]["is_valid"])
        self.assertEqual(extract_data["integrity"]["status"], "VERIFIED")
        self.assertEqual(
            extract_data["integrity"]["calculated_hash"],
            extract_data["integrity"]["expected_hash"]
        )

        extraction_id = extract_data["extraction_id"]

        # 4. Decrypt with CORRECT password
        decrypt_res = self.client.post(
            "/api/decrypt",
            json={
                "extraction_id": extraction_id,
                "password": self.password
            }
        )
        self.assertEqual(decrypt_res.status_code, 200)
        dec_data = json.loads(decrypt_res.data)
        self.assertTrue(dec_data["success"])
        self.assertEqual(dec_data["decrypted_message"], self.message)

        # 5. Decrypt with WRONG password
        wrong_pwd_res = self.client.post(
            "/api/decrypt",
            json={
                "extraction_id": extraction_id,
                "password": "WrongPassword@2026!"
            }
        )
        self.assertEqual(wrong_pwd_res.status_code, 401)
        wrong_data = json.loads(wrong_pwd_res.data)
        self.assertFalse(wrong_data["success"])
        self.assertIn("Incorrect password", wrong_data["error"])

        # 6. Tampered Payload Detection
        # Tamper stego image by altering pixel bytes inside the payload area (channel 350)
        stego_img = Image.open(io.BytesIO(stego_bytes)).convert("RGB")
        arr_tampered = np.array(stego_img)
        flat_tampered = arr_tampered.reshape(-1)
        flat_tampered[350] ^= 1  # Flip bit inside ciphertext payload
        tampered_img = Image.fromarray(flat_tampered.reshape(300, 300, 3))
        tampered_buf = io.BytesIO()
        tampered_img.save(tampered_buf, format="PNG")
        tampered_bytes = tampered_buf.getvalue()

        tampered_extract_res = self.client.post(
            "/api/extract-info",
            data={
                "image": (io.BytesIO(tampered_bytes), "tampered_stego.png")
            },
            content_type="multipart/form-data"
        )
        tampered_data = json.loads(tampered_extract_res.data)
        if tampered_data.get("success"):
            # Integrity check must detect the mismatch!
            self.assertFalse(tampered_data["integrity"]["is_valid"])
            self.assertEqual(tampered_data["integrity"]["status"], "TAMPERED_OR_CORRUPTED")
            # Attempting to decrypt tampered extraction must be refused!
            tampered_dec_res = self.client.post(
                "/api/decrypt",
                json={
                    "extraction_id": tampered_data["extraction_id"],
                    "password": self.password
                }
            )
            self.assertEqual(tampered_dec_res.status_code, 400)
            self.assertIn("aborted", json.loads(tampered_dec_res.data)["error"].lower())

        # 7. Performance Benchmark API
        bench_res = self.client.post(
            "/api/performance/run-test",
            json={"test_type": "full", "sample_image": "cyber_circuit"}
        )
        self.assertEqual(bench_res.status_code, 200)
        bench_data = json.loads(bench_res.data)
        self.assertTrue(bench_data["success"])
        self.assertEqual(bench_data["accuracy"]["recovery_accuracy_pct"], 100.0)
        self.assertEqual(bench_data["integrity"]["integrity_detection_rate_pct"], 100.0)

        # 8. Statistics API
        stats_res = self.client.get("/api/statistics")
        self.assertEqual(stats_res.status_code, 200)
        stats_data = json.loads(stats_res.data)
        self.assertTrue(stats_data["success"])
        self.assertGreaterEqual(stats_data["statistics"]["total_encodes"], 1)
        self.assertGreaterEqual(stats_data["statistics"]["total_decodes"], 1)


if __name__ == "__main__":
    unittest.main()
