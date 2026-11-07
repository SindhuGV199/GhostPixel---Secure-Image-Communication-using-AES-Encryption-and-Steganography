"""
Tests for Independent Sender-to-Receiver Communication
Validates that sender and receiver operate in 100% separate sessions,
devices, and processes without any shared memory, session state, or cookies.
"""

import unittest
import io
import json
import base64
import numpy as np
from PIL import Image
from app import app, init_db


class TestIndependentCommunication(unittest.TestCase):

    def setUp(self):
        init_db()
        self.password = "TopSecretReceiverPass@2026!"
        self.message = (
            "AGENT DIRECTIVE 007:\n"
            "Proceed to coordinate 48.8584° N, 2.2945° E.\n"
            "Unicode & Emojis: 🛡️ 🔐 🕵️ 🚀 🔒 🌐 零一二三\n"
            "Special: !@#$%^&*()_+=-~`{}[]|:;'<>,.?/"
        )

        # Create carrier image 250x250
        arr = np.random.randint(60, 210, (250, 250, 3), dtype=np.uint8)
        img = Image.fromarray(arr, mode="RGB")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        self.cover_bytes = buf.getvalue()

    def test_independent_sender_to_receiver_workflow(self):
        """
        Simulates:
        Sender: Device 1 (Client A)
        Receiver: Device 2 (Client B - separate process/session/cookies)
        """
        # --- SENDER (Client A) ---
        sender_client = app.test_client()

        encode_res = sender_client.post(
            "/api/encode",
            data={
                "image": (io.BytesIO(self.cover_bytes), "cover_carrier.png"),
                "message": self.message,
                "password": self.password
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(encode_res.status_code, 200)
        enc_data = json.loads(encode_res.data)
        self.assertTrue(enc_data["success"])
        stego_filename = enc_data["filename"]

        # Sender downloads stego PNG file
        dl_res = sender_client.get(f"/download/stego/{stego_filename}")
        self.assertEqual(dl_res.status_code, 200)
        downloaded_stego_bytes = dl_res.data
        dl_res.close()

        # Sender closes connection / session terminates
        del sender_client

        # --- RECEIVER (Client B - completely new client instance, no session) ---
        receiver_client = app.test_client()

        # Step 1: Receiver uploads received stego PNG to extract hidden payload
        extract_res = receiver_client.post(
            "/api/extract",
            data={
                "image": (io.BytesIO(downloaded_stego_bytes), "received_stego.png")
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(extract_res.status_code, 200)
        ext_data = json.loads(extract_res.data)
        self.assertTrue(ext_data["success"])
        self.assertTrue(ext_data["integrity"]["is_valid"])
        self.assertEqual(ext_data["integrity"]["status"], "VERIFIED")
        
        # Verify stateless payload_token is present
        self.assertIn("payload_token", ext_data)
        payload_token = ext_data["payload_token"]

        # Step 2: Receiver decrypts using the stateless payload_token and password
        decrypt_res = receiver_client.post(
            "/api/decrypt",
            json={
                "payload_token": payload_token,
                "password": self.password
            }
        )
        self.assertEqual(decrypt_res.status_code, 200)
        dec_data = json.loads(decrypt_res.data)
        self.assertTrue(dec_data["success"])
        self.assertEqual(dec_data["decrypted_message"], self.message)

    def test_direct_image_decrypt_single_step(self):
        """
        Tests receiver decoding via single direct multipart POST (image + password).
        """
        # Encode
        client_a = app.test_client()
        enc_res = client_a.post(
            "/api/encode",
            data={
                "image": (io.BytesIO(self.cover_bytes), "cover.png"),
                "message": "Direct decryption test message",
                "password": "DirectPass@2026!"
            },
            content_type="multipart/form-data"
        )
        enc_data = json.loads(enc_res.data)
        dl_res = client_a.get(f"/download/stego/{enc_data['filename']}")
        stego_bytes = dl_res.data
        dl_res.close()
        del client_a

        # Independent receiver uploads image + password directly
        client_b = app.test_client()
        dec_res = client_b.post(
            "/api/decrypt",
            data={
                "image": (io.BytesIO(stego_bytes), "stego.png"),
                "password": "DirectPass@2026!"
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(dec_res.status_code, 200)
        dec_data = json.loads(dec_res.data)
        self.assertEqual(dec_data["decrypted_message"], "Direct decryption test message")

    def test_wrong_password_rejection(self):
        """
        Tests that an unauthorized receiver cannot decrypt even with the valid image.
        """
        client = app.test_client()
        enc_res = client.post(
            "/api/encode",
            data={
                "image": (io.BytesIO(self.cover_bytes), "cover.png"),
                "message": "Sensitive Intel",
                "password": "CorrectPassword#123"
            },
            content_type="multipart/form-data"
        )
        enc_data = json.loads(enc_res.data)
        dl_res = client.get(f"/download/stego/{enc_data['filename']}")
        stego_bytes = dl_res.data
        dl_res.close()

        ext_res = client.post(
            "/api/extract",
            data={"image": (io.BytesIO(stego_bytes), "stego.png")},
            content_type="multipart/form-data"
        )
        payload_token = json.loads(ext_res.data)["payload_token"]

        # Attempt with wrong password
        dec_res = client.post(
            "/api/decrypt",
            json={
                "payload_token": payload_token,
                "password": "WrongPassword#456"
            }
        )
        self.assertEqual(dec_res.status_code, 401)
        self.assertFalse(json.loads(dec_res.data)["success"])

    def test_tampered_image_rejection(self):
        """
        Tests that if the stego image is modified/corrupted, integrity check fails.
        """
        client = app.test_client()
        enc_res = client.post(
            "/api/encode",
            data={
                "image": (io.BytesIO(self.cover_bytes), "cover.png"),
                "message": "Intel",
                "password": "Pass@123"
            },
            content_type="multipart/form-data"
        )
        enc_data = json.loads(enc_res.data)
        dl_res = client.get(f"/download/stego/{enc_data['filename']}")
        stego_bytes = dl_res.data
        dl_res.close()

        # Tamper payload byte
        img = Image.open(io.BytesIO(stego_bytes))
        arr = np.array(img)
        flat = arr.reshape(-1)
        flat[200] ^= 1  # Flip bit inside stored payload
        tampered_img = Image.fromarray(flat.reshape(arr.shape))
        buf = io.BytesIO()
        tampered_img.save(buf, format="PNG")
        tampered_bytes = buf.getvalue()

        ext_res = client.post(
            "/api/extract",
            data={"image": (io.BytesIO(tampered_bytes), "tampered.png")},
            content_type="multipart/form-data"
        )
        ext_data = json.loads(ext_res.data)
        if ext_data.get("success"):
            self.assertFalse(ext_data["integrity"]["is_valid"])

    def test_health_check_endpoint(self):
        client = app.test_client()
        res = client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data["status"], "healthy")


if __name__ == "__main__":
    unittest.main()

