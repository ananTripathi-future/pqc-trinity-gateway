"""
sanity_check.py — PQC 3-Layer Encryption Engine

Implements the cryptographic pipeline faithfully matching the C gateway:
  Layer 1: ML-KEM-768 (FIPS 203) — Key Encapsulation
  Layer 2: ML-DSA-65  (FIPS 204) — Digital Signatures
  Layer 3: AES-256-GCM           — Authenticated Symmetric Encryption

Designed to be imported by the Streamlit dashboard or run standalone.
"""

import os
import time
import threading
from kyber_py.ml_kem import ML_KEM_768
from dilithium_py.ml_dsa import ML_DSA_65
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Tuple, Dict, Any, Optional, Callable
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Layer Abstractions
# ---------------------------------------------------------------------------

class Layer1_KEM:
    """Quantum-Resistant KEM (ML-KEM-768, FIPS 203)"""

    ALGORITHM   = "ML-KEM-768"
    FIPS        = "FIPS 203"
    PK_BYTES    = 1184
    SK_BYTES    = 2400
    CT_BYTES    = 1088
    SS_BYTES    = 32
    NIST_LEVEL  = 3

    def __init__(self):
        self.pk, self.sk = ML_KEM_768.keygen()

    def encapsulate(self, peer_pk: bytes) -> Tuple[bytes, bytes]:
        """Returns (ciphertext, shared_secret)"""
        k, c = ML_KEM_768.encaps(peer_pk)
        return c, k

    def decapsulate(self, c: bytes) -> bytes:
        """Returns shared_secret"""
        return ML_KEM_768.decaps(self.sk, c)


class Layer2_Sig:
    """Authentication / Digital Signatures (ML-DSA-65, FIPS 204)"""

    ALGORITHM   = "ML-DSA-65"
    FIPS        = "FIPS 204"
    PK_BYTES    = 1952
    SK_BYTES    = 4032
    SIG_BYTES   = 3309
    NIST_LEVEL  = 3

    def __init__(self):
        self.pk, self.sk = ML_DSA_65.keygen()

    def sign(self, message: bytes) -> bytes:
        return ML_DSA_65.sign(self.sk, message)

    @staticmethod
    def verify(pk: bytes, message: bytes, signature: bytes) -> bool:
        return ML_DSA_65.verify(pk, message, signature)


class Layer3_AES:
    """Symmetric Wrapping (AES-256-GCM)"""

    ALGORITHM   = "AES-256-GCM"
    FIPS        = "NIST SP 800-38D"
    KEY_BITS    = 256
    NIST_LEVEL  = None          # symmetric — expressed as KEY_BITS instead
    NONCE_BYTES = 12
    TAG_BYTES   = 16

    def encrypt(self, key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
        aesgcm = AESGCM(key)
        nonce = os.urandom(self.NONCE_BYTES)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce, ciphertext

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass
class PQCResult:
    """Immutable result of a full 3-layer encryption round-trip."""
    status: str                           # "PASS" | "FAIL"
    plaintext: bytes = b""
    ciphertext_kem: bytes = b""
    nonce: bytes = b""
    ciphertext_aes: bytes = b""
    signature: bytes = b""
    decrypted_text: bytes = b""
    sig_verified: bool = False            # NEW: explicit verification flag
    metrics: Dict[str, float] = field(default_factory=dict)
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Core pipeline
# ---------------------------------------------------------------------------

def run_sanity_check(plaintext: bytes) -> Dict[str, Any]:
    """
    Execute the full 3-layer encrypt → sign → verify → decrypt pipeline.
    Returns a dict (backwards-compatible) with all intermediates and timing.
    """
    metrics: Dict[str, float] = {}

    # ── Initialization ──────────────────────────────────────────────────
    t0 = time.perf_counter()
    kem_alice = Layer1_KEM()
    kem_bob   = Layer1_KEM()
    sig_alice = Layer2_Sig()
    aes       = Layer3_AES()
    metrics["init_ms"] = (time.perf_counter() - t0) * 1000

    # ── Layer 1: KEM Encapsulation (Alice → Bob) ────────────────────────
    t0 = time.perf_counter()
    ciphertext_kem, shared_secret_alice = kem_alice.encapsulate(kem_bob.pk)
    metrics["kem_encaps_ms"] = (time.perf_counter() - t0) * 1000

    # ── Layer 1: KEM Decapsulation (Bob) ────────────────────────────────
    t0 = time.perf_counter()
    shared_secret_bob = kem_bob.decapsulate(ciphertext_kem)
    metrics["kem_decaps_ms"] = (time.perf_counter() - t0) * 1000

    assert shared_secret_alice == shared_secret_bob, "KEM shared secrets mismatch!"
    aes_key = shared_secret_alice

    # ── Layer 3: AES-256-GCM Encryption ─────────────────────────────────
    t0 = time.perf_counter()
    nonce, ciphertext_aes = aes.encrypt(aes_key, plaintext)
    metrics["aes_enc_ms"] = (time.perf_counter() - t0) * 1000

    # ── Layer 2: ML-DSA Signature Generation ────────────────────────────
    payload_to_sign = nonce + ciphertext_aes
    t0 = time.perf_counter()
    signature = sig_alice.sign(payload_to_sign)
    metrics["sig_sign_ms"] = (time.perf_counter() - t0) * 1000

    # ── Layer 2: ML-DSA Signature Verification ──────────────────────────
    t0 = time.perf_counter()
    sig_verified = Layer2_Sig.verify(sig_alice.pk, payload_to_sign, signature)
    metrics["sig_verify_ms"] = (time.perf_counter() - t0) * 1000

    # ── Layer 3: AES-256-GCM Decryption ─────────────────────────────────
    decrypted_text = b""
    if sig_verified:
        t0 = time.perf_counter()
        decrypted_text = aes.decrypt(shared_secret_bob, nonce, ciphertext_aes)
        metrics["aes_dec_ms"] = (time.perf_counter() - t0) * 1000
    else:
        metrics["aes_dec_ms"] = 0.0

    # ── Derived metrics ─────────────────────────────────────────────────
    pqc_time = metrics["kem_encaps_ms"] + metrics["kem_decaps_ms"] + \
               metrics["sig_sign_ms"] + metrics["sig_verify_ms"]
    aes_time = metrics["aes_enc_ms"] + metrics["aes_dec_ms"]
    total    = pqc_time + aes_time

    metrics["pqc_total_ms"]      = pqc_time
    metrics["aes_total_ms"]      = aes_time
    metrics["total_crypto_ms"]   = total
    metrics["pqc_overhead_pct"]  = (pqc_time / total * 100) if total > 0 else 0.0

    integrity_ok = sig_verified and (decrypted_text == plaintext)
    status = "PASS" if integrity_ok else "FAIL"

    return {
        "status":          status,
        "plaintext":       plaintext,
        "ciphertext_kem":  ciphertext_kem,
        "nonce":           nonce,
        "ciphertext_aes":  ciphertext_aes,
        "signature":       signature,
        "decrypted_text":  decrypted_text,
        "sig_verified":    sig_verified,
        "metrics":         metrics,
    }


# ---------------------------------------------------------------------------
# Async wrapper (for Streamlit background execution)
# ---------------------------------------------------------------------------

def run_sanity_check_async(
    plaintext: bytes,
    callback: Callable[[Dict[str, Any]], None],
) -> threading.Thread:
    """
    Run the 3-layer pipeline on a background thread and invoke *callback*
    with the result dict once complete. Returns the thread handle.
    """
    def _worker():
        result = run_sanity_check(plaintext)
        callback(result)

    t = threading.Thread(target=_worker, daemon=True, name="pqc-pipeline")
    t.start()
    return t


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_packet = b"CONFIDENTIAL_TRAFFIC_PAYLOAD_V1"
    r = run_sanity_check(test_packet)

    print("--- [PQC Trinity Gateway: Sanity Check] ---")
    print(f"  Original : {r['plaintext']}")
    print(f"  Decrypted: {r['decrypted_text']}")
    print(f"  Sig OK   : {r['sig_verified']}")
    print(f"  Status   : {r['status']}")
    print(f"  PQC overhead : {r['metrics']['pqc_overhead_pct']:.1f}%")
    print(f"  Metrics  : {r['metrics']}")
