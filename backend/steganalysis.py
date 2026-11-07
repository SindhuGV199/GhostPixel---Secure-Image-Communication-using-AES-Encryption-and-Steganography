"""
GhostPixel - Steganalysis Module
Implements Westfeld & Pfitzmann (1999) Chi-Square (χ²) Steganalysis
to detect statistical Pairs of Values (PoV) equalization in image LSBs.
"""

from typing import Dict, Any
import numpy as np
from PIL import Image
from scipy.stats import chi2


def analyze_chi_square(image: Image.Image) -> Dict[str, Any]:
    """
    Performs Chi-Square (χ²) steganalysis on an RGB image.
    
    Mathematical Principle:
    In natural images, frequencies of adjacent pixel values (2k, 2k+1) differ due to lighting
    and texture gradients. When pseudo-random LSB data (such as AES ciphertext) is embedded,
    these frequencies equalize.
    
    A low chi-square statistic relative to degrees of freedom yields a p-value close to 1.0,
    indicating that frequency equalization is consistent with steganographic embedding.
    """
    if image.mode != "RGB":
        image = image.convert("RGB")

    arr = np.array(image, dtype=np.uint8)
    flat = arr.reshape(-1)
    
    # 256-bin histogram of pixel channel intensities
    hist, _ = np.histogram(flat, bins=256, range=(0, 256))

    chi_stat = 0.0
    valid_pairs = 0

    for k in range(128):
        count_even = float(hist[2 * k])
        count_odd = float(hist[2 * k + 1])
        expected = (count_even + count_odd) / 2.0

        # Apply standard statistical threshold for Chi-Square applicability
        if expected > 5.0:
            chi_stat += ((count_even - expected) ** 2) / expected
            valid_pairs += 1

    df = max(1, valid_pairs - 1)
    
    # Survival function: P(X >= chi_stat) for chi-square distribution with df degrees of freedom
    # In steganalysis, a p-value close to 1.0 indicates observed variation is consistent with
    # artificial equalization (random LSB embedding).
    p_val = float(chi2.sf(chi_stat, df))
    stego_prob = max(0.0, min(1.0, p_val))
    prob_pct = round(stego_prob * 100.0, 2)

    if prob_pct >= 85.0:
        verdict = "Steganographic Embedding Detected (High Confidence)"
        interpretation = (
            f"Chi-square value ({chi_stat:.2f}) is significantly lower than natural expectation (df={df}), "
            "indicating artificial equalization of adjacent pixel values (PoV) caused by LSB embedding."
        )
    elif prob_pct >= 50.0:
        verdict = "Suspicious Equalization (Moderate Confidence)"
        interpretation = (
            f"Observed statistical distribution shows partial equalization ({prob_pct}%). "
            "Possible light steganographic embedding or low carrier utilization."
        )
    else:
        verdict = "Natural Unaltered Carrier (No Stego Detected)"
        interpretation = (
            f"High Chi-square variance ({chi_stat:.2f} with df={df}) confirms natural unequal distributions "
            "characteristic of pristine, unmodulated photography."
        )

    return {
        "chi_square_stat": round(float(chi_stat), 2),
        "degrees_of_freedom": int(df),
        "p_value": round(float(p_val), 6),
        "stego_probability_pct": prob_pct,
        "verdict": verdict,
        "interpretation": interpretation
    }

