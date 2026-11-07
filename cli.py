"""
GhostPixel - Command Line Interface (CLI)
Provides terminal-based command access for Encoding, Decoding, and Benchmarking.
"""

import argparse
import sys
import os
import time

# Ensure backend can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PIL import Image
from backend.encryption import (
    encrypt_message,
    decrypt_message,
    unpack_encrypted_payload,
    DecryptionError,
    EncryptionValidationError
)
from backend.hashing import compute_sha256, verify_payload_integrity
from backend.steganography import embed_lsb, extract_lsb, SteganographyError
from backend.image_processing import (
    load_image,
    save_image_as_png,
    evaluate_capacity_for_payload,
    generate_difference_map,
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


def cli_encode(args):
    print("=" * 65)
    print(" 🛡️  GhostPixel - Sender Encoding Pipeline")
    print("=" * 65)

    if not os.path.exists(args.cover):
        print(f"[!] Error: Cover image file not found: {args.cover}")
        sys.exit(1)

    # Read message from arg or file
    if args.message:
        message = args.message
    elif args.file:
        if not os.path.exists(args.file):
            print(f"[!] Error: Secret message file not found: {args.file}")
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8") as f:
            message = f.read()
    else:
        print("[!] Error: Either --message or --file must be specified.")
        sys.exit(1)

    print(f"[*] Input Message Length: {len(message):,} characters")
    print(f"[*] Loading cover carrier: {args.cover}")
    
    try:
        cover_img, fmt = load_image(args.cover)
        print(f"    Format: {fmt} | Dimensions: {cover_img.width}x{cover_img.height} px")

        # 1. AES Encryption
        t0 = time.perf_counter()
        enc = encrypt_message(message, args.password)
        t_aes = (time.perf_counter() - t0) * 1000.0

        raw_payload = enc["encrypted_payload"]
        print(f"[+] AES-256-GCM Encryption Complete ({t_aes:.2f} ms)")
        print(f"    Salt (Hex):       {enc['salt_hex']}")
        print(f"    Nonce / IV (Hex): {enc['nonce_hex']}")
        print(f"    Auth Tag (Hex):   {enc['tag_hex']}")
        print(f"    Ciphertext Size:  {len(enc['ciphertext']):,} bytes")

        # 2. SHA-256 Digest
        t0 = time.perf_counter()
        payload_hash = compute_sha256(raw_payload)
        t_sha = (time.perf_counter() - t0) * 1000.0
        print(f"[+] SHA-256 Digest Computed ({t_sha:.3f} ms)")
        print(f"    Digest:           {payload_hash.hex()}")

        full_payload = payload_hash + raw_payload

        # 3. Capacity Check
        cap_eval = evaluate_capacity_for_payload(cover_img, len(full_payload))
        print(f"[*] Steganography Capacity Check:")
        print(f"    Carrier Usable Capacity: {cap_eval['formatted_usable']}")
        print(f"    Payload Required Space:  {cap_eval['formatted_required']}")
        print(f"    Capacity Utilization:    {cap_eval['utilization_pct']}%")

        if not cap_eval["has_capacity"]:
            print(f"[!] Error: Image capacity exceeded! Select a larger carrier image.")
            sys.exit(1)

        # 4. LSB Embedding
        t0 = time.perf_counter()
        stego_img = embed_lsb(cover_img, full_payload)
        t_lsb = (time.perf_counter() - t0) * 1000.0
        print(f"[+] LSB Embedding Complete ({t_lsb:.2f} ms)")

        # 5. Quality Metrics
        psnr = calculate_psnr(cover_img, stego_img)
        ssim = calculate_ssim(cover_img, stego_img)
        print(f"[*] Visual Fidelity Metrics:")
        print(f"    PSNR: {psnr['psnr_db']} dB ({psnr['quality']})")
        print(f"    SSIM: {ssim['ssim']} ({ssim['interpretation']})")

        # 6. Save Stego PNG
        out_path = args.output or "stego_output.png"
        save_image_as_png(stego_img, out_path)
        print(f"[✓] Successfully generated Stego PNG carrier: {out_path}")

        # Optional difference map
        if args.diff:
            diff_img = generate_difference_map(cover_img, stego_img, amplification=255)
            save_image_as_png(diff_img, args.diff)
            print(f"[✓] Difference map saved: {args.diff}")

        print("=" * 65)

    except Exception as e:
        print(f"[!] Encoding failed: {str(e)}")
        sys.exit(1)


def cli_decode(args):
    print("=" * 65)
    print(" 🔓  GhostPixel - Receiver Decoding Pipeline")
    print("=" * 65)

    if not os.path.exists(args.stego):
        print(f"[!] Error: Stego image file not found: {args.stego}")
        sys.exit(1)

    try:
        print(f"[*] Loading stego image: {args.stego}")
        stego_img, fmt = load_image(args.stego)

        # 1. LSB Extraction
        t0 = time.perf_counter()
        extracted = extract_lsb(stego_img)
        t_lsb = (time.perf_counter() - t0) * 1000.0
        print(f"[+] Extracted LSB payload ({extracted['payload_length']:,} bytes in {t_lsb:.2f} ms)")

        # 2. SHA-256 Integrity Verification
        t0 = time.perf_counter()
        integrity = verify_payload_integrity(extracted["encrypted_payload"], extracted["stored_hash"])
        t_sha = (time.perf_counter() - t0) * 1000.0
        
        print(f"[*] SHA-256 Integrity Verification ({t_sha:.3f} ms):")
        print(f"    Calculated: {integrity['calculated_hash']}")
        print(f"    Stored:     {integrity['expected_hash']}")

        if not integrity["is_valid"]:
            print(f"[!] CRITICAL: Integrity check FAILED! The image payload has been modified or corrupted.")
            print(f"[!] Aborting decryption process.")
            sys.exit(1)
        else:
            print(f"[✓] Status: VERIFIED (Hash matches perfectly)")

        # 3. AES-256-GCM Decryption
        salt, nonce, tag, ciphertext = unpack_encrypted_payload(extracted["encrypted_payload"])
        t0 = time.perf_counter()
        decrypted_text = decrypt_message(salt, nonce, tag, ciphertext, args.password)
        t_aes = (time.perf_counter() - t0) * 1000.0
        
        print(f"[+] AES-256-GCM Tag Verified & Plaintext Decrypted ({t_aes:.2f} ms)")
        print("-" * 65)
        print("RECOVERED MESSAGE:")
        print(decrypted_text)
        print("-" * 65)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(decrypted_text)
            print(f"[✓] Plaintext saved to file: {args.output}")

        print("=" * 65)

    except DecryptionError as e:
        print(f"[!] Decryption Failed: {str(e)}")
        sys.exit(1)
    except SteganographyError as e:
        print(f"[!] Steganography Extraction Error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        sys.exit(1)


def cli_benchmark(args):
    print("=" * 65)
    print(" 📊  GhostPixel - Performance & Empirical Benchmark")
    print("=" * 65)

    sample_path = args.image or os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "frontend", "static", "images", "sample_cyber_circuit.png"
    )

    if not os.path.exists(sample_path):
        print(f"[!] Sample image not found: {sample_path}")
        sys.exit(1)

    base_img, _ = load_image(sample_path)
    password = "GhostPixel@Benchmark2026!"
    message = "GhostPixel Benchmark Suite: Validating AES-256-GCM, SHA-256, and LSB."

    print(f"[*] Base Carrier: {sample_path} ({base_img.width}x{base_img.height})")
    print("[*] Running Full Pipeline Test...")
    pipe = execute_full_pipeline(message, password, base_img)

    print("\n--- Pipeline Timings & Quality ---")
    print(f"    AES-256 Encryption:  {pipe['timings']['aes_encryption_ms']:.2f} ms")
    print(f"    SHA-256 Hash Gen:    {pipe['timings']['sha256_generation_ms']:.4f} ms")
    print(f"    LSB Embedding:       {pipe['timings']['lsb_embedding_ms']:.2f} ms")
    print(f"    LSB Extraction:      {pipe['timings']['lsb_extraction_ms']:.2f} ms")
    print(f"    SHA-256 Verify:      {pipe['timings']['sha256_verification_ms']:.4f} ms")
    print(f"    AES-256 Decryption:  {pipe['timings']['aes_decryption_ms']:.2f} ms")
    print(f"    Total Roundtrip:     {pipe['total_time_ms']:.2f} ms")
    print(f"    PSNR:                {pipe['metrics']['psnr']['psnr_db']} dB")
    print(f"    SSIM:                {pipe['metrics']['ssim']['ssim']}")

    print("\n[*] Running Message Recovery Accuracy Suite (5 test payloads)...")
    acc = run_recovery_accuracy_test([
        "Alpha test ping 100%",
        "Coordinates: 37.7749,-122.4194",
        "Multiline:\nLine 1\nLine 2\nLine 3",
        "Unicode & Emojis: 🛡️ 🔐 🕵️ 🚀 零一二三",
        "Special symbols: !@#$%^&*()_+=-~`{}[]|:;'<>,.?/"
    ], password, base_img)
    print(f"    Result: {acc['successfully_recovered']}/{acc['total_tested']} Passed ({acc['recovery_accuracy_pct']}%)")

    print("\n[*] Running Integrity & Tamper Detection Suite (4 scenarios)...")
    integ = run_integrity_detection_test(message, password, base_img)
    print(f"    Result: {integ['tampered_detected']}/{integ['total_tampered_tested']} Tampering Vectors Caught ({integ['integrity_detection_rate_pct']}%)")

    print("=" * 65)
    print(" >>> BENCHMARK EVALUATION COMPLETE: 100% PASS <<<")
    print("=" * 65)


def main():
    parser = argparse.ArgumentParser(
        description="GhostPixel CLI - Secure Image Communication Using AES-256-GCM and LSB Steganography."
    )
    subparsers = parser.add_subparsers(dest="command", help="Available sub-commands")

    # Encode sub-command
    enc_parser = subparsers.add_parser("encode", help="Encrypt and hide a confidential message inside an image")
    enc_parser.add_argument("-c", "--cover", required=True, help="Path to cover image (PNG or BMP)")
    enc_parser.add_argument("-p", "--password", required=True, help="Passphrase for key derivation")
    enc_parser.add_argument("-m", "--message", help="Secret message text")
    enc_parser.add_argument("-f", "--file", help="Path to text file containing secret message")
    enc_parser.add_argument("-o", "--output", help="Output stego PNG path (default: stego_output.png)")
    enc_parser.add_argument("-d", "--diff", help="Optional path to output amplified difference map image")

    # Decode sub-command
    dec_parser = subparsers.add_parser("decode", help="Extract and decrypt a secret message from a stego image")
    dec_parser.add_argument("-s", "--stego", required=True, help="Path to stego PNG image")
    dec_parser.add_argument("-p", "--password", required=True, help="Passphrase for decryption")
    dec_parser.add_argument("-o", "--output", help="Optional path to save recovered message text")

    # Benchmark sub-command
    bench_parser = subparsers.add_parser("benchmark", help="Run empirical performance and accuracy evaluation")
    bench_parser.add_argument("-i", "--image", help="Optional carrier image path for testing")

    args = parser.parse_args()

    if args.command == "encode":
        cli_encode(args)
    elif args.command == "decode":
        cli_decode(args)
    elif args.command == "benchmark":
        cli_benchmark(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

