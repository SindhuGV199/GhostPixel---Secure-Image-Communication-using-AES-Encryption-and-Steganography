"""
GhostPixel - Secure Image Communication Using AES-256-GCM Encryption and LSB Steganography
Main Flask Application Server
"""

import os
import uuid
import time
import io
import base64
from datetime import datetime, timezone
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    send_file,
    send_from_directory,
    abort
)
from PIL import Image

from backend.encryption import (
    encrypt_message,
    decrypt_message,
    unpack_encrypted_payload,
    evaluate_password_strength,
    DecryptionError,
    EncryptionValidationError
)
from backend.hashing import (
    compute_sha256,
    compute_sha256_hex,
    verify_payload_integrity
)
from backend.steganography import (
    embed_lsb,
    extract_lsb,
    SteganographyError,
    HEADER_SIZE
)
from backend.image_processing import (
    load_image,
    calculate_image_capacity,
    evaluate_capacity_for_payload,
    save_image_as_png,
    generate_difference_map,
    extract_bit_plane,
    ImageProcessingError,
    InsufficientCapacityError
)
from backend.performance import (
    calculate_psnr,
    calculate_ssim,
    execute_full_pipeline,
    run_recovery_accuracy_test,
    run_integrity_detection_test
)
from backend.database import (
    init_db,
    log_activity,
    log_benchmark,
    get_recent_activities,
    get_system_statistics
)

# Application Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
STEGO_DIR = os.path.join(UPLOAD_DIR, "stego")
COVERS_DIR = os.path.join(UPLOAD_DIR, "covers")
SAMPLES_DIR = os.path.join(UPLOAD_DIR, "samples")
DIFFS_DIR = os.path.join(UPLOAD_DIR, "diffs")

for d in (UPLOAD_DIR, STEGO_DIR, COVERS_DIR, SAMPLES_DIR, DIFFS_DIR):
    os.makedirs(d, exist_ok=True)

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "frontend", "templates"),
    static_folder=os.path.join(BASE_DIR, "frontend", "static")
)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32 MB max file upload
app.config["SECRET_KEY"] = os.urandom(24)

# In-memory temporary cache for extracted payload sessions
# extraction_id -> { "stored_hash": bytes, "encrypted_payload": bytes, "timestamp": float }
EXTRACTION_CACHE = {}


def cleanup_old_temporary_files(max_age_seconds: int = 7200):
    """
    Cleans up temporary generated carrier files older than max_age_seconds (default 2 hours).
    Ensures storage does not accumulate indefinitely in production deployments.
    """
    now = time.time()
    for directory in (STEGO_DIR, COVERS_DIR, DIFFS_DIR):
        try:
            if not os.path.exists(directory):
                continue
            for fname in os.listdir(directory):
                fpath = os.path.join(directory, fname)
                if os.path.isfile(fpath):
                    if now - os.path.getmtime(fpath) > max_age_seconds:
                        try:
                            os.remove(fpath)
                        except OSError:
                            pass
        except Exception:
            pass


@app.before_request
def setup_on_startup():
    # Ensure database schema is initialized
    init_db()
    # Prune old temporary files periodically
    if request.path.startswith("/api/encode"):
        cleanup_old_temporary_files()


@app.route("/api/health")
def api_health():
    """Health check endpoint for deployment monitoring (Render, Railway, Kubernetes)."""
    return jsonify({
        "status": "healthy",
        "service": "GhostPixel Cryptographic Engine",
        "version": "2.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


# ==========================================
# PAGE ROUTES
# ==========================================

@app.route("/")
def index():
    """Home / Landing Dashboard"""
    stats = get_system_statistics()
    return render_template("index.html", stats=stats)


@app.route("/encode")
def encode_page():
    """Sender Module - Encode Message"""
    return render_template("encode.html")


@app.route("/decode")
def decode_page():
    """Receiver Module - Decode Message"""
    return render_template("decode.html")


@app.route("/performance")
def performance_page():
    """Performance Evaluation Module"""
    stats = get_system_statistics()
    activities = get_recent_activities(limit=10)
    return render_template("performance.html", stats=stats, activities=activities)


@app.route("/security")
def security_page():
    """Security Information and Cryptographic Architecture"""
    return render_template("security.html")


@app.route("/about")
def about_page():
    """About GhostPixel Project"""
    return render_template("about.html")


# ==========================================
# API: SENDER / ENCODING
# ==========================================

@app.route("/api/validate-password", methods=["POST"])
def api_validate_password():
    """Validates password strength and returns criteria breakdown."""
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    evaluation = evaluate_password_strength(password)
    return jsonify({"success": True, "evaluation": evaluation})


@app.route("/api/check-capacity", methods=["POST"])
def api_check_capacity():
    """
    Checks if an uploaded image has sufficient capacity for a given message length.
    """
    if "image" not in request.files:
        return jsonify({"success": False, "error": "No image file provided."}), 400

    file = request.files["image"]
    message_text = request.form.get("message", "")
    
    try:
        img_bytes = file.read()
        if not img_bytes:
            return jsonify({"success": False, "error": "Uploaded image file is empty."}), 400

        img, img_format = load_image(img_bytes)
        
        # Estimate required payload size:
        # 32 (SHA-256) + 16 (Salt) + 12 (Nonce) + 16 (Tag) + msg_len + 8 (Stego Header)
        msg_bytes_len = len(message_text.encode("utf-8")) if message_text else 0
        # If no message provided yet, calculate with nominal estimate (e.g. 100 bytes)
        nominal_payload_size = 32 + 16 + 12 + 16 + (msg_bytes_len if msg_bytes_len > 0 else 64)

        eval_result = evaluate_capacity_for_payload(img, nominal_payload_size)
        
        return jsonify({
            "success": True,
            "format": img_format,
            "width": img.width,
            "height": img.height,
            "file_size_bytes": len(img_bytes),
            "file_size_formatted": f"{round(len(img_bytes)/1024, 1)} KB",
            "capacity": eval_result
        })

    except ImageProcessingError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to check capacity: {str(e)}"}), 500


@app.route("/api/encode", methods=["POST"])
def api_encode():
    """
    Executes the full Sender Encoding Workflow:
    1. Validates inputs (message, password, image).
    2. AES-256-GCM encryption with PBKDF2-derived key (unique salt, nonce).
    3. SHA-256 hash generation of payload for integrity verification.
    4. Image capacity check.
    5. LSB steganography into RGB pixel channels.
    6. Saves stego PNG image.
    7. Computes PSNR, SSIM, and processing times.
    8. Logs event to SQLite.
    """
    if "image" not in request.files:
        return jsonify({"success": False, "error": "No image file provided."}), 400

    file = request.files["image"]
    message = request.form.get("message", "").strip()
    password = request.form.get("password", "")

    if not message:
        return jsonify({"success": False, "error": "Secret message cannot be empty."}), 400
    if not password:
        return jsonify({"success": False, "error": "Password cannot be empty."}), 400

    try:
        img_bytes = file.read()
        if not img_bytes:
            return jsonify({"success": False, "error": "Uploaded image file is empty."}), 400

        # Load and validate cover image
        cover_image, img_format = load_image(img_bytes)

        # 1. AES-256-GCM Encryption Timing
        t0 = time.perf_counter()
        enc = encrypt_message(message, password)
        t_aes_enc = (time.perf_counter() - t0) * 1000.0

        raw_payload = enc["encrypted_payload"]

        # 2. SHA-256 Hash Calculation Timing
        t0 = time.perf_counter()
        payload_hash = compute_sha256(raw_payload)
        t_sha = (time.perf_counter() - t0) * 1000.0

        # Complete packet = Stored Hash (32B) + Encrypted Payload
        full_payload = payload_hash + raw_payload

        # 3. LSB Embedding Timing
        t0 = time.perf_counter()
        stego_image = embed_lsb(cover_image, full_payload)
        t_lsb = (time.perf_counter() - t0) * 1000.0

        # 4. Performance & Quality Evaluation
        psnr_info = calculate_psnr(cover_image, stego_image)
        ssim_info = calculate_ssim(cover_image, stego_image)
        cap_info = evaluate_capacity_for_payload(cover_image, len(full_payload))

        total_time_ms = t_aes_enc + t_sha + t_lsb

        # 5. Save Stego PNG to disk
        stego_filename = f"stego_{uuid.uuid4().hex[:12]}.png"
        stego_filepath = os.path.join(STEGO_DIR, stego_filename)
        save_image_as_png(stego_image, stego_filepath)

        # Save Cover image copy for side-by-side preview if needed
        cover_filename = f"cover_{uuid.uuid4().hex[:12]}.png"
        cover_filepath = os.path.join(COVERS_DIR, cover_filename)
        save_image_as_png(cover_image, cover_filepath)

        # Generate amplified difference map for steganalysis inspection
        diff_img = generate_difference_map(cover_image, stego_image, amplification=255)
        diff_filename = f"diff_{uuid.uuid4().hex[:12]}.png"
        diff_filepath = os.path.join(DIFFS_DIR, diff_filename)
        save_image_as_png(diff_img, diff_filepath)

        # 6. Log to SQLite
        log_activity(
            operation="ENCODE",
            status="SUCCESS",
            image_name=file.filename or "uploaded_image",
            message_len=len(message),
            payload_size=len(full_payload),
            psnr=psnr_info["psnr_db"],
            ssim=ssim_info["ssim"],
            processing_time_ms=round(total_time_ms, 2),
            details=f"Cover {cover_image.width}x{cover_image.height}, PSNR: {psnr_info['psnr_db']}dB"
        )

        return jsonify({
            "success": True,
            "message": "Message successfully encrypted and embedded into stego image!",
            "download_url": f"/download/stego/{stego_filename}",
            "stego_preview_url": f"/view/stego/{stego_filename}",
            "cover_preview_url": f"/view/cover/{cover_filename}",
            "diff_preview_url": f"/view/diff/{diff_filename}",
            "filename": stego_filename,
            "image_details": {
                "width": cover_image.width,
                "height": cover_image.height,
                "format": img_format,
                "output_format": "PNG (Lossless)"
            },
            "cryptographic_details": {
                "algorithm": "AES-256-GCM",
                "kdf": "PBKDF2-HMAC-SHA256 (100,000 rounds)",
                "salt_hex": enc["salt_hex"],
                "nonce_hex": enc["nonce_hex"],
                "tag_hex": enc["tag_hex"],
                "ciphertext_bytes": len(enc["ciphertext"]),
                "sha256_hash_hex": payload_hash.hex()
            },
            "metrics": {
                "psnr": psnr_info,
                "ssim": ssim_info,
                "capacity": cap_info,
                "timings": {
                    "aes_encryption_ms": round(t_aes_enc, 2),
                    "sha256_generation_ms": round(t_sha, 4),
                    "lsb_embedding_ms": round(t_lsb, 2),
                    "total_processing_ms": round(total_time_ms, 2)
                }
            }
        })

    except InsufficientCapacityError as e:
        return jsonify({"success": False, "error": str(e)}), 422
    except EncryptionValidationError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except ImageProcessingError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"An unexpected error occurred: {str(e)}"}), 500


# ==========================================
# API: RECEIVER / DECODING
# ==========================================

@app.route("/api/extract", methods=["POST"])
@app.route("/api/extract-info", methods=["POST"])
def api_extract_info():
    """
    Step 1 & 2 of Receiver Workflow:
    Extracts LSB payload, computes fresh SHA-256 hash, and compares with stored hash.
    Does NOT require password yet; verifies payload integrity first.
    Completely stateless: generates a self-contained payload_token for the receiver
    so no server session or local state is required between extract and decrypt.
    """
    if "image" not in request.files:
        return jsonify({"success": False, "error": "No stego image file provided."}), 400

    file = request.files["image"]
    try:
        img_bytes = file.read()
        if not img_bytes:
            return jsonify({"success": False, "error": "Uploaded image file is empty."}), 400

        stego_image, img_format = load_image(img_bytes)

        # LSB Extraction Timing
        t0 = time.perf_counter()
        extracted = extract_lsb(stego_image)
        t_extract = (time.perf_counter() - t0) * 1000.0

        # SHA-256 Integrity Verification Timing
        t0 = time.perf_counter()
        integrity = verify_payload_integrity(extracted["encrypted_payload"], extracted["stored_hash"])
        t_sha = (time.perf_counter() - t0) * 1000.0

        # Unpack encrypted payload headers to inspect metadata safely
        salt, nonce, tag, ciphertext = unpack_encrypted_payload(extracted["encrypted_payload"])

        # Self-contained stateless payload token:
        # Base64 of: [Stored Hash: 32 bytes] + [Encrypted Payload: (16 salt + 12 nonce + 16 tag + N ciphertext)]
        raw_combined = extracted["stored_hash"] + extracted["encrypted_payload"]
        payload_token = base64.b64encode(raw_combined).decode("ascii")

        # In-memory cache as fallback for backward compatibility
        extraction_id = uuid.uuid4().hex
        EXTRACTION_CACHE[extraction_id] = {
            "stored_hash": extracted["stored_hash"],
            "encrypted_payload": extracted["encrypted_payload"],
            "salt": salt,
            "nonce": nonce,
            "tag": tag,
            "ciphertext": ciphertext,
            "integrity_passed": integrity["is_valid"],
            "created_at": time.time()
        }

        # Log extraction event
        log_activity(
            operation="EXTRACT",
            status="VERIFIED" if integrity["is_valid"] else "TAMPERED",
            image_name=file.filename or "stego_image",
            payload_size=extracted["payload_length"],
            processing_time_ms=round(t_extract + t_sha, 2),
            details=f"Integrity {integrity['status']}, Calculated: {integrity['calculated_hash'][:16]}..."
        )

        return jsonify({
            "success": True,
            "extraction_id": extraction_id,
            "payload_token": payload_token,
            "integrity": integrity,
            "payload_info": {
                "total_payload_bytes": extracted["payload_length"],
                "ciphertext_bytes": len(ciphertext),
                "salt_hex": salt.hex(),
                "nonce_hex": nonce.hex(),
                "tag_hex": tag.hex(),
                "format": img_format,
                "dimensions": f"{stego_image.width}x{stego_image.height}"
            },
            "timings": {
                "lsb_extraction_ms": round(t_extract, 2),
                "sha256_verification_ms": round(t_sha, 4)
            }
        })

    except SteganographyError as e:
        return jsonify({"success": False, "error": str(e)}), 422
    except ImageProcessingError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to extract hidden data: {str(e)}"}), 500


@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    """
    Step 3 of Receiver Workflow:
    Completely stateless decryption. Accepts either:
    1. payload_token (base64 extracted packet) + password
    2. Direct multipart upload of stego image + password
    3. extraction_id (in-memory fallback)
    
    Enforces SHA-256 integrity check and AES-256-GCM authentication.
    Recovers original message.
    """
    req_json = request.get_json(silent=True) or {}
    password = request.form.get("password") or req_json.get("password", "")
    payload_token = request.form.get("payload_token") or req_json.get("payload_token", "")
    extraction_id = request.form.get("extraction_id") or req_json.get("extraction_id", "")

    if not password:
        return jsonify({"success": False, "error": "Password is required for decryption."}), 400

    try:
        # Case 1: Stateless payload token provided
        if payload_token:
            try:
                raw_combined = base64.b64decode(payload_token.encode("ascii"))
            except Exception:
                return jsonify({"success": False, "error": "Invalid payload token format."}), 400

            if len(raw_combined) < 32 + 16 + 12 + 16:
                return jsonify({"success": False, "error": "Payload token is too short or corrupted."}), 400

            stored_hash = raw_combined[:32]
            encrypted_payload = raw_combined[32:]

            # Independent SHA-256 Integrity Verification
            integrity = verify_payload_integrity(encrypted_payload, stored_hash)
            if not integrity["is_valid"]:
                return jsonify({
                    "success": False,
                    "error": "Decryption aborted: Payload integrity verification failed! The hidden data has been tampered with or corrupted."
                }), 400

            salt, nonce, tag, ciphertext = unpack_encrypted_payload(encrypted_payload)
            payload_size = len(encrypted_payload)

        # Case 2: In-memory cached extraction fallback
        elif extraction_id and extraction_id in EXTRACTION_CACHE:
            cached = EXTRACTION_CACHE[extraction_id]
            if not cached["integrity_passed"]:
                return jsonify({
                    "success": False,
                    "error": "Decryption aborted: Payload integrity verification failed! The hidden data has been tampered with or corrupted."
                }), 400

            salt = cached["salt"]
            nonce = cached["nonce"]
            tag = cached["tag"]
            ciphertext = cached["ciphertext"]
            payload_size = len(cached["encrypted_payload"])

        # Case 3: Direct image upload + password
        elif "image" in request.files:
            file = request.files["image"]
            img_bytes = file.read()
            stego_image, _ = load_image(img_bytes)
            extracted = extract_lsb(stego_image)

            # Strict integrity verification
            integrity = verify_payload_integrity(extracted["encrypted_payload"], extracted["stored_hash"])
            if not integrity["is_valid"]:
                return jsonify({
                    "success": False,
                    "error": "Decryption aborted: SHA-256 integrity verification failed. Data was modified or corrupted!"
                }), 400

            salt, nonce, tag, ciphertext = unpack_encrypted_payload(extracted["encrypted_payload"])
            payload_size = len(extracted["encrypted_payload"])
        else:
            return jsonify({
                "success": False,
                "error": "No valid extraction session or image provided. Please extract the image first or upload it with password."
            }), 400

        # AES-256-GCM Decryption Timing
        t0 = time.perf_counter()
        decrypted_message = decrypt_message(salt, nonce, tag, ciphertext, password)
        t_aes_dec = (time.perf_counter() - t0) * 1000.0

        # Log to SQLite
        log_activity(
            operation="DECODE",
            status="SUCCESS",
            message_len=len(decrypted_message),
            payload_size=payload_size,
            processing_time_ms=round(t_aes_dec, 2),
            details="AES-256-GCM authenticated decryption successful."
        )

        return jsonify({
            "success": True,
            "message": "Message successfully decrypted and verified!",
            "decrypted_message": decrypted_message,
            "message_length": len(decrypted_message),
            "decryption_time_ms": round(t_aes_dec, 2),
            "authentication_status": "AUTHENTICATED (AES-256-GCM Tag Verified)"
        })

    except DecryptionError as e:
        log_activity(
            operation="DECODE",
            status="FAILED",
            details=f"Decryption failed: {str(e)}"
        )
        return jsonify({
            "success": False,
            "error": str(e)
        }), 401
    except Exception as e:
        return jsonify({"success": False, "error": f"Decryption error: {str(e)}"}), 500


# ==========================================
# API: PERFORMANCE & BENCHMARKING
# ==========================================

@app.route("/api/performance/run-test", methods=["POST"])
def api_run_performance_test():
    """
    Executes live performance benchmarks:
    - Recovery accuracy across test messages
    - Integrity detection rate across tampering scenarios
    - Timing benchmarks and PSNR/SSIM evaluation
    """
    data = request.get_json(silent=True) or {}
    test_type = data.get("test_type", "full")  # "full", "accuracy", "integrity", "speed"
    custom_message = data.get("custom_message", "").strip()
    image_choice = data.get("sample_image", "cyber_circuit")

    # Pick base sample image
    sample_file_map = {
        "cyber_circuit": "sample_cyber_circuit.png",
        "nebula": "sample_nebula.png",
        "shield": "sample_shield.png"
    }
    sample_filename = sample_file_map.get(image_choice, "sample_cyber_circuit.png")
    sample_path = os.path.join(SAMPLES_DIR, sample_filename)

    if not os.path.exists(sample_path):
        # Generate sample on the fly if missing
        base_img = Image.new("RGB", (400, 400), (20, 30, 50))
    else:
        base_img, _ = load_image(sample_path)

    password = "GhostPixel@Benchmark2026!"

    try:
        response_data = {"success": True, "test_type": test_type}

        if test_type in ("full", "speed"):
            # Execute full pipeline with single custom or standard message
            test_msg = custom_message if custom_message else (
                "GhostPixel Benchmark Suite 2026: Verifying AES-256-GCM encryption, "
                "PBKDF2-HMAC-SHA256 key derivation, SHA-256 hash integrity check, "
                "and RGB LSB steganographic embedding and extraction fidelity."
            )
            pipe_res = execute_full_pipeline(test_msg, password, base_img)
            response_data["pipeline"] = {
                "is_exact_match": pipe_res["is_exact_match"],
                "message_length": pipe_res["message_length"],
                "payload_size": pipe_res["payload_size"],
                "total_time_ms": pipe_res["total_time_ms"],
                "timings": pipe_res["timings"],
                "metrics": pipe_res["metrics"]
            }

        if test_type in ("full", "accuracy"):
            # Run Recovery Accuracy suite
            test_msgs = [
                "Short ping message: 100% test.",
                "Medium message with numeric coordinates: Lat 37.7749, Lon -122.4194, Elevation 150m.",
                "Multiline cryptographic log:\n[INFO] Initializing cipher...\n[SEC] AES-GCM tag OK\n[END]",
                "Special & Unicode characters: !@#$%^&*()_+ 🛡️ 🔐 🕵️ 🚀 零一二三",
                "Long narrative text: GhostPixel provides complete covert communication by combining military-grade "
                "authenticated encryption with pixel-level steganography. Even if an adversary intercepts the cover image, "
                "it remains visually identical to the original carrier image."
            ]
            if custom_message:
                test_msgs.append(custom_message)

            acc_res = run_recovery_accuracy_test(test_msgs, password, base_img)
            response_data["accuracy"] = acc_res

            # Log benchmark run to DB
            log_benchmark(
                test_type="RECOVERY_ACCURACY",
                total_cases=acc_res["total_tested"],
                passed_cases=acc_res["successfully_recovered"],
                accuracy_pct=acc_res["recovery_accuracy_pct"],
                details=acc_res
            )

        if test_type in ("full", "integrity"):
            # Run Integrity Detection suite
            integ_msg = custom_message or "Confidential message for integrity detection testing."
            integ_res = run_integrity_detection_test(integ_msg, password, base_img)
            response_data["integrity"] = integ_res

            # Log benchmark run to DB
            log_benchmark(
                test_type="INTEGRITY_DETECTION",
                total_cases=integ_res["total_tampered_tested"],
                passed_cases=integ_res["tampered_detected"],
                integrity_rate_pct=integ_res["integrity_detection_rate_pct"],
                details=integ_res
            )

        return jsonify(response_data)

    except Exception as e:
        return jsonify({"success": False, "error": f"Performance evaluation failed: {str(e)}"}), 500


@app.route("/api/statistics", methods=["GET"])
def api_statistics():
    """Returns database summary statistics."""
    stats = get_system_statistics()
    recent = get_recent_activities(limit=10)
    return jsonify({
        "success": True,
        "statistics": stats,
        "recent_activities": recent
    })


@app.route("/api/samples", methods=["GET"])
def api_samples():
    """Lists available sample cover images for 1-click testing."""
    samples = [
        {
            "id": "cyber_circuit",
            "name": "Cyber Circuit (500x400)",
            "width": 500,
            "height": 400,
            "capacity_kb": 73.2,
            "url": "/static/images/sample_cyber_circuit.png"
        },
        {
            "id": "nebula",
            "name": "Cosmic Nebula (450x450)",
            "width": 450,
            "height": 450,
            "capacity_kb": 74.1,
            "url": "/static/images/sample_nebula.png"
        },
        {
            "id": "shield",
            "name": "Security Shield (400x400)",
            "width": 400,
            "height": 400,
            "capacity_kb": 58.5,
            "url": "/static/images/sample_shield.png"
        }
    ]
    return jsonify({"success": True, "samples": samples})


# ==========================================
# FILE DOWNLOAD AND PREVIEW ROUTES
# ==========================================

@app.route("/download/stego/<filename>")
def download_stego(filename):
    """Downloads generated stego PNG image as an attachment."""
    safe_filename = os.path.basename(filename)
    filepath = os.path.join(STEGO_DIR, safe_filename)
    if not os.path.exists(filepath):
        abort(404)
    return send_file(filepath, as_attachment=True, download_name=safe_filename, mimetype="image/png")


@app.route("/view/stego/<filename>")
def view_stego(filename):
    """Serves stego image inline for browser preview."""
    safe_filename = os.path.basename(filename)
    filepath = os.path.join(STEGO_DIR, safe_filename)
    if not os.path.exists(filepath):
        abort(404)
    return send_file(filepath, mimetype="image/png")


@app.route("/view/cover/<filename>")
def view_cover(filename):
    """Serves cover image inline for browser preview."""
    safe_filename = os.path.basename(filename)
    filepath = os.path.join(COVERS_DIR, safe_filename)
    if not os.path.exists(filepath):
        abort(404)
    return send_file(filepath, mimetype="image/png")


@app.route("/view/diff/<filename>")
def view_diff(filename):
    """Serves amplified difference map image inline for steganalysis inspection."""
    safe_filename = os.path.basename(filename)
    filepath = os.path.join(DIFFS_DIR, safe_filename)
    if not os.path.exists(filepath):
        abort(404)
    return send_file(filepath, mimetype="image/png")


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")
    debug = os.environ.get("FLASK_ENV") != "production"

    print("==================================================================")
    print(f" 🚀 GhostPixel Server Starting on http://{host}:{port}")
    print(" AES-256-GCM Encryption | SHA-256 Integrity | LSB Steganography")
    print("==================================================================")
    app.run(host=host, port=port, debug=debug)

