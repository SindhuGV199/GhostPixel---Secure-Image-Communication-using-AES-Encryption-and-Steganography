"""
Tests for AES-256-GCM Encryption and PBKDF2 Key Derivation.
"""

import unittest
from backend.encryption import (
    encrypt_message,
    decrypt_message,
    unpack_encrypted_payload,
    evaluate_password_strength,
    DecryptionError,
    EncryptionValidationError,
    SALT_SIZE,
    NONCE_SIZE,
    TAG_SIZE
)


class TestEncryption(unittest.TestCase):

    def setUp(self):
        self.password = "TopSecret@2026!"
        self.message = "Classified GhostPixel payload: Coordinates (37.7749, -122.4194)."

    def test_encrypt_decrypt_roundtrip(self):
        enc = encrypt_message(self.message, self.password)
        self.assertEqual(len(enc["salt"]), SALT_SIZE)
        self.assertEqual(len(enc["nonce"]), NONCE_SIZE)
        self.assertEqual(len(enc["tag"]), TAG_SIZE)

        s, n, tg, ct = unpack_encrypted_payload(enc["encrypted_payload"])
        decrypted = decrypt_message(s, n, tg, ct, self.password)
        self.assertEqual(decrypted, self.message)

    def test_wrong_password_rejection(self):
        enc = encrypt_message(self.message, self.password)
        s, n, tg, ct = unpack_encrypted_payload(enc["encrypted_payload"])
        with self.assertRaises(DecryptionError):
            decrypt_message(s, n, tg, ct, "WrongPassword#123")

    def test_tampered_ciphertext_rejection(self):
        enc = encrypt_message(self.message, self.password)
        s, n, tg, ct = unpack_encrypted_payload(enc["encrypted_payload"])
        
        # Corrupt one byte of ciphertext
        tampered_ct = bytearray(ct)
        tampered_ct[0] ^= 0x01
        
        with self.assertRaises(DecryptionError):
            decrypt_message(s, n, tg, bytes(tampered_ct), self.password)

    def test_tampered_tag_rejection(self):
        enc = encrypt_message(self.message, self.password)
        s, n, tg, ct = unpack_encrypted_payload(enc["encrypted_payload"])

        # Corrupt one byte of authentication tag
        tampered_tg = bytearray(tg)
        tampered_tg[0] ^= 0x01

        with self.assertRaises(DecryptionError):
            decrypt_message(s, n, bytes(tampered_tg), ct, self.password)

    def test_multiline_and_special_characters(self):
        complex_msg = (
            "Line 1: Normal text\n"
            "Line 2: Tab\tIndented\n"
            "Line 3: Symbols !@#$%^&*()_+=-~`{}[]|:;'<>,.?/\n"
            "Line 4: Unicode & Emojis: 🛡️ 🔐 🕵️ 🚀 🔒 🌐 零一二三\n"
            "Line 5: Arabic: سر أمني مشفر\n"
            "Line 6: Numbers 0123456789\n"
        )
        enc = encrypt_message(complex_msg, self.password)
        s, n, tg, ct = unpack_encrypted_payload(enc["encrypted_payload"])
        decrypted = decrypt_message(s, n, tg, ct, self.password)
        self.assertEqual(decrypted, complex_msg)

    def test_empty_message_validation(self):
        with self.assertRaises(EncryptionValidationError):
            encrypt_message("", self.password)
        with self.assertRaises(EncryptionValidationError):
            encrypt_message("   ", self.password)

    def test_empty_password_validation(self):
        with self.assertRaises(EncryptionValidationError):
            encrypt_message(self.message, "")

    def test_nonce_and_salt_uniqueness(self):
        enc1 = encrypt_message(self.message, self.password)
        enc2 = encrypt_message(self.message, self.password)
        # Even with identical plaintext and password, salt and nonce must be unique
        self.assertNotEqual(enc1["salt"], enc2["salt"])
        self.assertNotEqual(enc1["nonce"], enc2["nonce"])
        self.assertNotEqual(enc1["ciphertext"], enc2["ciphertext"])

    def test_password_strength_evaluator(self):
        res_weak = evaluate_password_strength("abc")
        self.assertFalse(res_weak["passed"])

        res_strong = evaluate_password_strength("SuperSecureP@ssw0rd2026")
        self.assertTrue(res_strong["passed"])
        self.assertEqual(res_strong["label"], "Very Strong")


if __name__ == "__main__":
    unittest.main()

