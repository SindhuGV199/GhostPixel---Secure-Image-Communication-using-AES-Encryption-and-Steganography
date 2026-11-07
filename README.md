# GhostPixel – Secure Image Communication Platform

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Cryptography AES-GCM](https://img.shields.io/badge/cryptography-AES--256--GCM-green.svg)](https://cryptography.io/)
[![Steganography RGB LSB](https://img.shields.io/badge/steganography-RGB%20LSB-cyan.svg)](https://pillow.readthedocs.io/)
[![Tests Passing](https://img.shields.io/badge/tests-39%2F39%20passed-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](https://opensource.org/licenses/MIT)

**GhostPixel** is a fully functional, production-ready cybersecurity web application and CLI tool that enables **real-world, independent sender-to-receiver covert communication**. It tightly integrates three core cryptographic and steganographic primitives:

1. **AES-256-GCM Authenticated Encryption** with PBKDF2-HMAC-SHA256 key derivation.
2. **SHA-256 Cryptographic Hashing** for end-to-end payload integrity and early tamper detection.
3. **RGB Least Significant Bit (LSB) Steganography** to embed ciphertext invisibly inside ordinary carrier images.

---

## 🌐 Real-World Sender-to-Receiver Architecture

GhostPixel is architected as two **completely independent workflows** that do not depend on the same browser session, device, or local storage:

```
[SENDER on Device A (New York)]
  │
  ├─ 1. Opens GhostPixel Sender Portal (/encode)
  ├─ 2. Enters Secret Message & Password
  ├─ 3. Uploads Cover Image (PNG or BMP)
  ├─ 4. AES-256-GCM Encrypts + SHA-256 Digested + LSB Embedded
  └─ 5. Downloads Stego Image (.png)
         │
         ▼
[OUT-OF-BAND SECURE TRANSMISSION]
  Send PNG file via Email, Telegram (as File/Doc), WhatsApp (as Document), or AirDrop.
  Share passphrase securely out-of-band (e.g. Signal or in person).
         │
         ▼
[RECEIVER on Device B (Tokyo)]
  │
  ├─ 1. Opens GhostPixel Receiver Portal (/decode) independently
  ├─ 2. Uploads the received Stego PNG
  ├─ 3. Clicks "Extract Hidden Message & Verify SHA-256 Integrity"
  ├─ 4. SHA-256 hash verified -> Status: VERIFIED
  ├─ 5. Enters passphrase -> AES-256-GCM authenticates tag
  └─ 6. Recovers original plaintext message!
```

---

## 🌟 Key Features

- **100% Stateless Communication:** The generated PNG stego carrier is completely self-contained. It encapsulates the 4-byte magic signature (`GPX1`), 4-byte payload length, 32-byte SHA-256 digest, 16-byte random salt, 12-byte nonce, 16-byte authentication tag, and the ciphertext. No server session or database record is required for decoding.
- **Genuine Cryptographic Pipeline:** No simulated data. Uses hardware-accelerated AES-256-GCM authenticated encryption and constant-time SHA-256 digest checks (`hmac.compare_digest`).
- **Strict Key Derivation:** PBKDF2-HMAC-SHA256 with 100,000 rounds and a 16-byte random salt prevents rainbow table attacks.
- **Unique Per-Message IV:** A fresh 96-bit (12-byte) random nonce is generated for every transmission.
- **Early Tamper Detection:** Verifies the SHA-256 hash of the extracted payload before user authentication, halting decryption immediately if payload tampering or pixel corruption is detected.
- **Lossless PNG Enforcement:** Output images are saved strictly as lossless PNGs to prevent lossy compression algorithms (like JPEG) from altering LSB bits.
- **Visual Steganalysis (Difference Map):** Generates a 255x amplified difference map showing the exact pixel bits modulated by the steganographic engine.
- **Empirical Performance Evaluation:** Computes actual Peak Signal-to-Noise Ratio (PSNR in dB), Structural Similarity Index (SSIM), execution latency per stage (in ms), recovery accuracy, and tamper detection rates.
- **Modern Cyber Dark UI:** Styled with a dark navy background, subtle purple/cyan neon accents, live capacity gauges, password strength meters, and side-by-side comparison previews.
- **CLI Utility (`cli.py`):** Standalone terminal tool for encoding, decoding, and benchmarking.
- **Deployment Ready:** Configured with `gunicorn`, `Procfile`, environment variable ports, health check API (`/api/health`), and automatic temporary file cleanup.

---

## 🛠️ Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Backend** | Python 3.12, Flask 3.1, RESTful APIs, Gunicorn |
| **Security & Ciphers** | `cryptography` (AES-256-GCM, PBKDF2HMAC, SHA256), `hashlib`, `hmac` |
| **Image Processing** | Pillow (PIL), NumPy (Vectorized bit packing), SciPy (SSIM filtering) |
| **Database** | SQLite 3 (Persistent audit logging) |
| **Frontend** | HTML5, CSS3 (Cyberpunk dark theme, responsive grid), Vanilla JavaScript |

---

## 📁 Project Structure

```
GhostPixel/
├── app.py                      # Main Flask application and REST routes
├── cli.py                      # Standalone CLI interface for terminal users
├── requirements.txt            # Project dependencies
├── Procfile                    # Production server definition (Gunicorn)
├── README.md                   # Comprehensive documentation
│
├── backend/
│   ├── __init__.py             # Backend package marker
│   ├── encryption.py           # AES-256-GCM & PBKDF2 key derivation
│   ├── hashing.py              # SHA-256 hashing & integrity verification
│   ├── integrity.py            # 4-Stage Transmission Integrity Verification engine
│   ├── steganography.py        # RGB LSB embedding & extraction
│   ├── image_processing.py     # Image loading, capacity checks, difference maps
│   ├── steganalysis.py         # Chi-Square (χ²) steganalysis detection engine
│   ├── performance.py          # PSNR, SSIM, latency & benchmark suites
│   └── database.py             # SQLite activity and benchmark logging
│
├── frontend/
│   ├── templates/
│   │   ├── base.html           # Master navigation & footer layout
│   │   ├── index.html          # Landing dashboard with Sender & Receiver portals
│   │   ├── encode.html         # Dedicated Sender Portal (Message -> Stego PNG)
│   │   ├── decode.html         # Dedicated Receiver Portal (Stego PNG -> Plaintext)
│   │   ├── performance.html    # Empirical benchmark suite & metrics visualizer
│   │   ├── security.html       # Cryptographic breakdown & LSB simulator
│   │   └── about.html          # Project architecture & specifications
│   │
│   └── static/
│       ├── css/style.css       # Dark navy cyberpunk styling
│       ├── js/main.js          # Reactive UI, drag & drop, API client
│       └── images/             # Sample images (Cyber Circuit, Nebula, Shield)
│
├── tests/
│   ├── __init__.py             # Test suite package marker
│   ├── test_encryption.py      # Unit tests for AES-256-GCM and PBKDF2
│   ├── test_hashing.py         # Unit tests for SHA-256 integrity
│   ├── test_steganography.py   # Unit tests for LSB embedding & extraction
│   ├── test_performance.py     # Unit tests for PSNR, SSIM, and accuracy
│   ├── test_end_to_end.py      # Full integration test through Flask test client
│   ├── test_independent_communication.py # Independent sender-receiver session tests
│   ├── test_transmission_integrity.py   # Transmission integrity, JPEG, resize, crop tests
│   └── test_live_flow.py       # Live pipeline verification script
│
└── uploads/
    ├── covers/                 # Temporary storage of cover images
    ├── stego/                  # Generated stego PNG carrier files
    ├── diffs/                  # Visual difference maps (255x amplified)
    ├── samples/                # High-resolution benchmark cover images
    └── ghostpixel.db           # Persistent SQLite database
```

---

## 🚀 Installation & Local Execution

### Prerequisites
- Python 3.10, 3.11, or 3.12 installed on your system.

### Step 1: Clone or Navigate to the Directory
```bash
cd c:\Users\sindu\OneDrive\Desktop\GhostPixel
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Run the Application
```bash
python app.py
```

The application will start on:
```
http://127.0.0.1:5000
```
Open your browser and navigate to **`http://127.0.0.1:5000`**.

---

## 💻 CLI Usage

GhostPixel provides a command-line interface via `cli.py`:

### 1. Encode a Message into an Image
```bash
python cli.py encode -c frontend/static/images/sample_cyber_circuit.png -m "Classified directive" -p "SecretPass@2026" -o stego_intel.png -d diff_map.png
```

### 2. Decode a Message from a Stego Image
```bash
python cli.py decode -s stego_intel.png -p "SecretPass@2026"
```

### 3. Run Performance Benchmarks
```bash
python cli.py benchmark
```

---

## 🧪 Running Automated Tests

Run the full automated test suite (31 tests across all modules):

```bash
python -m unittest discover tests
```

Expected output:
```text
.......................................
----------------------------------------------------------------------
Ran 39 tests in 5.347s

OK
```

---

## ☁️ Deployment Guide (Render / Railway / Heroku)

GhostPixel is pre-configured for one-click cloud deployment:

### Deploying to Render
1. Push your repository to GitHub.
2. In Render Dashboard, click **New +** &rarr; **Web Service**.
3. Connect your repository.
4. Set:
   - **Environment:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app --workers 4 --timeout 120`
5. Click **Create Web Service**.

### Health Check Endpoint
GhostPixel provides a standard monitoring endpoint at:
```
GET /api/health
```
Response:
```json
{
  "status": "healthy",
  "service": "GhostPixel Cryptographic Engine",
  "version": "2.0.0",
  "timestamp": "2026-11-06T15:18:24.123456+00:00"
}
```

---

## 💡 Best Practices for Real-World Sharing

When sharing generated stego images with a remote receiver:
1. **Send as an Uncompressed Document / File:**
   - **Telegram:** Click the paperclip &rarr; choose **File** (not Photo).
   - **WhatsApp:** Click the attachment icon &rarr; choose **Document** (not Gallery/Photo).
   - **Email:** Attach the PNG file directly.
   - **Why?** Social media apps compress photos into lossy JPEGs, which alters the least significant bits. Sending as an uncompressed document preserves 100% of the pixel bits.
2. **Share the Passphrase Out-of-Band:**
   - Transmit your passphrase over a separate secure channel (e.g. Signal or verbal exchange).
