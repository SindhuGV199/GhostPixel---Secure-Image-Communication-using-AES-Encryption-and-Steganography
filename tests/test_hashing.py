"""
Tests for SHA-256 Hashing and Integrity Verification.
"""

import unittest
from backend.hashing import (
    compute_sha256,
    compute_sha256_hex,
    verify_sha256,
    verify_payload_integrity
)


class TestHashing(unittest.TestCase):

    def setUp(self):
        self.sample_data = b"Encrypted_Payload_Block_Test_GhostPixel_2026"

    def test_sha256_output_properties(self):
        digest = compute_sha256(self.sample_data)
        self.assertEqual(len(digest), 32)

        digest_hex = compute_sha256_hex(self.sample_data)
        self.assertEqual(len(digest_hex), 64)
        self.assertEqual(digest.hex(), digest_hex)

    def test_integrity_verification_success(self):
        digest = compute_sha256(self.sample_data)
        is_valid, calc_hex, exp_hex = verify_sha256(self.sample_data, digest)
        self.assertTrue(is_valid)
        self.assertEqual(calc_hex, exp_hex)

        result = verify_payload_integrity(self.sample_data, digest)
        self.assertTrue(result["is_valid"])
        self.assertEqual(result["status"], "VERIFIED")

    def test_integrity_verification_failure_on_tamper(self):
        original_digest = compute_sha256(self.sample_data)
        
        # Tamper single bit
        tampered_data = bytearray(self.sample_data)
        tampered_data[0] ^= 0x01
        tampered_data = bytes(tampered_data)

        is_valid, calc_hex, exp_hex = verify_sha256(tampered_data, original_digest)
        self.assertFalse(is_valid)
        self.assertNotEqual(calc_hex, exp_hex)

        result = verify_payload_integrity(tampered_data, original_digest)
        self.assertFalse(result["is_valid"])
        self.assertEqual(result["status"], "TAMPERED_OR_CORRUPTED")

    def test_type_error_on_non_bytes(self):
        with self.assertRaises(TypeError):
            compute_sha256("Not bytes")


if __name__ == "__main__":
    unittest.main()

