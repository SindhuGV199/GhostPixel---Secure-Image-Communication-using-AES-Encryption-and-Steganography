"""
Tests for Performance Metrics: PSNR, SSIM, Timings, Recovery Accuracy, and Integrity Detection.
"""

import unittest
import numpy as np
from PIL import Image

from backend.performance import (
    calculate_psnr,
    calculate_ssim,
    execute_full_pipeline,
    run_recovery_accuracy_test,
    run_integrity_detection_test
)


class TestPerformance(unittest.TestCase):

    def setUp(self):
        # Create 150x150 test image
        arr = np.random.randint(60, 200, (150, 150, 3), dtype=np.uint8)
        self.image = Image.fromarray(arr, mode="RGB")
        self.password = "SecTest#2026!"
        self.message = "Top Secret Evaluation Payload."

    def test_psnr_identical_images(self):
        res = calculate_psnr(self.image, self.image)
        self.assertTrue(res["is_identical"])
        self.assertEqual(res["psnr_db"], 100.0)

    def test_psnr_after_lsb_modification(self):
        # Embed message and verify high PSNR (> 50 dB)
        pipeline = execute_full_pipeline(self.message, self.password, self.image)
        psnr_db = pipeline["metrics"]["psnr"]["psnr_db"]
        self.assertGreater(psnr_db, 50.0)

    def test_ssim_identical_images(self):
        res = calculate_ssim(self.image, self.image)
        self.assertAlmostEqual(res["ssim"], 1.0, places=4)

    def test_ssim_after_lsb_modification(self):
        pipeline = execute_full_pipeline(self.message, self.password, self.image)
        ssim_val = pipeline["metrics"]["ssim"]["ssim"]
        self.assertGreater(ssim_val, 0.999)

    def test_recovery_accuracy_suite(self):
        messages = [
            "Alpha test payload 1",
            "Beta payload with numbers: 1234567890",
            "Gamma payload with special chars: @#$%^&*()",
            "Delta multiline\nSecond line\nThird line",
            "Epsilon with emojis: 🛡️ 🔐 🕵️"
        ]
        acc_result = run_recovery_accuracy_test(messages, self.password, self.image)
        self.assertEqual(acc_result["total_tested"], 5)
        self.assertEqual(acc_result["successfully_recovered"], 5)
        self.assertEqual(acc_result["recovery_accuracy_pct"], 100.0)

    def test_integrity_detection_rate_suite(self):
        detect_result = run_integrity_detection_test(self.message, self.password, self.image)
        self.assertGreaterEqual(detect_result["total_tampered_tested"], 3)
        self.assertEqual(detect_result["tampered_detected"], detect_result["total_tampered_tested"])
        self.assertEqual(detect_result["integrity_detection_rate_pct"], 100.0)

    def test_execution_timings_presence(self):
        pipeline = execute_full_pipeline(self.message, self.password, self.image)
        timings = pipeline["timings"]
        self.assertIn("aes_encryption_ms", timings)
        self.assertIn("sha256_generation_ms", timings)
        self.assertIn("lsb_embedding_ms", timings)
        self.assertIn("lsb_extraction_ms", timings)
        self.assertIn("sha256_verification_ms", timings)
        self.assertIn("aes_decryption_ms", timings)
        self.assertGreater(pipeline["total_time_ms"], 0.0)


if __name__ == "__main__":
    unittest.main()

