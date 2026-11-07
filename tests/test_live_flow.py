"""
Live User Flow Test Script
"""

import os
import sys
import io
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

def run_live_flow():
    client = app.test_client()

    # 1. Encode with sample image
    with open('frontend/static/images/sample_cyber_circuit.png', 'rb') as f:
        img_data = f.read()

    msg = 'TOP SECRET: Agent rendezvous confirmed at 0400Z. Vector 37.7749,-122.4194. Key verified.'
    pwd = 'CyberSecurity#2026!'

    res = client.post('/api/encode', data={
        'image': (io.BytesIO(img_data), 'sample_cyber_circuit.png'),
        'message': msg,
        'password': pwd
    }, content_type='multipart/form-data')

    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    data = json.loads(res.data)
    assert data['success'] is True
    stego_file = data['filename']
    psnr_val = data['metrics']['psnr']['psnr_db']
    ssim_val = data['metrics']['ssim']['ssim']
    print(f"1. ENCODE SUCCESS: Stego saved as {stego_file}, PSNR: {psnr_val} dB, SSIM: {ssim_val}")

    # 2. Download stego image
    dl_res = client.get(f"/download/stego/{stego_file}")
    assert dl_res.status_code == 200
    stego_bytes = dl_res.data
    print(f"2. DOWNLOAD SUCCESS: Received {len(stego_bytes)} bytes stego PNG")

    # 3. Extract & verify integrity
    ext_res = client.post('/api/extract-info', data={
        'image': (io.BytesIO(stego_bytes), 'stego.png')
    }, content_type='multipart/form-data')
    assert ext_res.status_code == 200
    ext_data = json.loads(ext_res.data)
    assert ext_data['integrity']['is_valid'] is True
    calc_hash = ext_data['integrity']['calculated_hash']
    print(f"3. INTEGRITY VERIFIED: SHA-256 {calc_hash[:24]}... matches stored hash!")

    # 4. Decrypt with correct password
    dec_res = client.post('/api/decrypt', json={
        'extraction_id': ext_data['extraction_id'],
        'password': pwd
    })
    assert dec_res.status_code == 200
    dec_data = json.loads(dec_res.data)
    assert dec_data['decrypted_message'] == msg
    t_dec = dec_data['decryption_time_ms']
    print(f"4. DECRYPT SUCCESS: Exact match confirmed! Length: {len(msg)} chars in {t_dec} ms")

    # 5. Decrypt with WRONG password
    wrong_res = client.post('/api/decrypt', json={
        'extraction_id': ext_data['extraction_id'],
        'password': 'InvalidPassword!'
    })
    assert wrong_res.status_code == 401
    print("5. WRONG PASSWORD REJECTION: Correctly rejected with 401 Unauthorized.")

    # 6. Performance benchmark execution
    bench_res = client.post('/api/performance/run-test', json={
        'test_type': 'full',
        'sample_image': 'cyber_circuit'
    })
    assert bench_res.status_code == 200
    b_data = json.loads(bench_res.data)
    acc_pct = b_data['accuracy']['recovery_accuracy_pct']
    integ_pct = b_data['integrity']['integrity_detection_rate_pct']
    print(f"6. BENCHMARK COMPLETE: Recovery Accuracy: {acc_pct}%, Integrity Detection Rate: {integ_pct}%")

    print("\n>>> ALL VALIDATION GATES PASSED WITH 100% SUCCESS! <<<")

if __name__ == '__main__':
    run_live_flow()
