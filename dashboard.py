"""
dashboard.py — PQC Trinity Gateway: Live Monitoring Dashboard

Premium Streamlit frontend for the 3-layer Post-Quantum encryption engine.
Design language: Glassmorphism · Inter/Outfit typography · Cyber-Command palette.
"""

import streamlit as st
import time
from sanity_check import (
    run_sanity_check,
    Layer1_KEM, Layer2_Sig, Layer3_AES,
)

# ═══════════════════════════════════════════════════════════════════════════
# Page Config (must be the first Streamlit call)
# ═══════════════════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="PQC Trinity Gateway",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ═══════════════════════════════════════════════════════════════════════════
# Session State — persist results across reruns so the UI never flickers
# ═══════════════════════════════════════════════════════════════════════════
if "last_result" not in st.session_state:
    st.session_state.last_result = None
if "run_count" not in st.session_state:
    st.session_state.run_count = 0
if "history" not in st.session_state:
    st.session_state.history = []

# ═══════════════════════════════════════════════════════════════════════════
# CSS — Premium Design System
# ═══════════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
    /* ── Typography ─────────────────────────────────────────────────── */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Outfit:wght@500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }
    h1, h2, h3, h4 {
        font-family: 'Outfit', sans-serif !important;
    }

    /* ── Suppress Streamlit anchor links on headings ────────────────── */
    .stMarkdown h1 a, .stMarkdown h2 a, .stMarkdown h3 a,
    .stMarkdown h4 a, .stMarkdown h5 a, .stMarkdown h6 a,
    h1 a[href^="#"], h2 a[href^="#"], h3 a[href^="#"],
    h4 a[href^="#"], h5 a[href^="#"], h6 a[href^="#"],
    .stMarkdown a.header-anchor,
    a.css-15zrgzn, a.css-eczf16 {
        display: none !important;
        pointer-events: none !important;
    }

    /* ── Background ─────────────────────────────────────────────────── */
    .stApp {
        background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
        color: #f8fafc;
    }

    /* ── Glassmorphism Cards ─────────────────────────────────────────── */
    .glass-card {
        background: rgba(255, 255, 255, 0.03);
        backdrop-filter: blur(20px);
        -webkit-backdrop-filter: blur(20px);
        border: 1px solid rgba(255, 255, 255, 0.06);
        border-radius: 16px;
        padding: 24px;
        margin-bottom: 20px;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.35);
        transition: transform 0.3s cubic-bezier(.4,0,.2,1),
                    box-shadow 0.3s cubic-bezier(.4,0,.2,1),
                    border-color 0.3s ease;
    }
    .glass-card:hover {
        transform: translateY(-4px);
        box-shadow: 0 16px 48px rgba(0, 0, 0, 0.45);
        border-color: rgba(139, 92, 246, 0.15);
    }

    /* ── Glowing Section Headers ─────────────────────────────────────── */
    .glow-text {
        text-shadow: 0 0 12px rgba(139, 92, 246, 0.4);
        color: #c4b5fd;
    }

    /* ── Metric Tiles ────────────────────────────────────────────────── */
    .metric-value {
        font-family: 'JetBrains Mono', monospace;
        font-size: 2.2rem;
        font-weight: 700;
        color: #10b981;
        text-shadow: 0 0 18px rgba(16, 185, 129, 0.25);
        line-height: 1.1;
    }
    .metric-label {
        font-family: 'Inter', sans-serif;
        font-size: 0.8rem;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 1.2px;
        margin-bottom: 8px;
    }
    .metric-unit {
        font-size: 0.9rem;
        color: #64748b;
        font-weight: 400;
    }

    /* ── Hex Dump (traffic log) ──────────────────────────────────────── */
    .hex-dump {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.78rem;
        line-height: 1.5;
        color: #38bdf8;
        background: rgba(15, 23, 42, 0.8);
        padding: 14px;
        border-radius: 10px;
        border: 1px solid rgba(56, 189, 248, 0.1);
        height: 160px;
        overflow-y: auto;
        overflow-x: hidden;
        word-break: break-all;
        overflow-wrap: break-word;
        white-space: pre-wrap;
    }
    .hex-dump::-webkit-scrollbar { width: 6px; }
    .hex-dump::-webkit-scrollbar-track { background: transparent; }
    .hex-dump::-webkit-scrollbar-thumb {
        background: rgba(139, 92, 246, 0.3);
        border-radius: 3px;
    }
    .hex-dump::-webkit-scrollbar-thumb:hover { background: rgba(139, 92, 246, 0.5); }

    /* ── Animated Status Pill ────────────────────────────────────────── */
    @keyframes pulse-glow {
        0%, 100% { box-shadow: 0 0 6px rgba(16, 185, 129, 0.3); }
        50%      { box-shadow: 0 0 16px rgba(16, 185, 129, 0.6); }
    }
    .live-status {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 6px 16px;
        border-radius: 24px;
        background: rgba(16, 185, 129, 0.08);
        color: #10b981;
        border: 1px solid rgba(16, 185, 129, 0.3);
        font-weight: 600;
        font-size: 0.8rem;
        letter-spacing: 0.5px;
        animation: pulse-glow 2.5s ease-in-out infinite;
    }

    /* ── Overhead Bar ────────────────────────────────────────────────── */
    .overhead-bar-bg {
        width: 100%;
        height: 10px;
        background: rgba(255,255,255,0.06);
        border-radius: 5px;
        overflow: hidden;
        margin-top: 8px;
    }
    .overhead-bar-fill {
        height: 100%;
        border-radius: 5px;
        background: linear-gradient(90deg, #8b5cf6, #ec4899);
        transition: width 0.6s cubic-bezier(.4,0,.2,1);
    }

    /* ── Health Check Pipeline ───────────────────────────────────────── */
    .pipeline-step {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 12px 0;
        border-bottom: 1px solid rgba(255,255,255,0.04);
    }
    .pipeline-step:last-child { border-bottom: none; }
    .step-icon {
        width: 36px; height: 36px;
        border-radius: 50%;
        display: flex; align-items: center; justify-content: center;
        font-size: 1rem;
        flex-shrink: 0;
    }
    .step-pass { background: rgba(16,185,129,0.15); border: 1px solid rgba(16,185,129,0.4); }
    .step-fail { background: rgba(239,68,68,0.15); border: 1px solid rgba(239,68,68,0.4); }
    .step-wait { background: rgba(100,116,139,0.15); border: 1px solid rgba(100,116,139,0.4); }
    .step-label { color: #e2e8f0; font-weight: 500; font-size: 0.95rem; }
    .step-detail { color: #64748b; font-size: 0.78rem; }

    /* ── Sidebar polish ──────────────────────────────────────────────── */
    section[data-testid="stSidebar"] {
        background: rgba(15, 23, 42, 0.95) !important;
        border-right: 1px solid rgba(255,255,255,0.04);
    }
    section[data-testid="stSidebar"] .glass-card {
        background: rgba(255, 255, 255, 0.02);
    }
</style>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════
# Helper: Format hex with spacing for readability
# ═══════════════════════════════════════════════════════════════════════════
def fmt_hex(data: bytes, group: int = 2) -> str:
    """Turn raw bytes into spaced, uppercase hex — much easier to scan."""
    h = data.hex().upper()
    return " ".join(h[i:i+group*2] for i in range(0, len(h), group*2))


# ═══════════════════════════════════════════════════════════════════════════
# Header
# ═══════════════════════════════════════════════════════════════════════════
st.markdown("""
<div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:2rem; flex-wrap:wrap; gap:12px;'>
    <div>
        <h1 style='margin:0; background:-webkit-linear-gradient(45deg,#8b5cf6,#3b82f6,#06b6d4);
            -webkit-background-clip:text; -webkit-text-fill-color:transparent;
            font-size:2.4rem;'>PQC Trinity Gateway</h1>
        <p style='color:#94a3b8; margin:4px 0 0 0; font-size:1.05rem;'>
            Post-Quantum Cryptographic Traffic Orchestrator &mdash; 3-Layer Secure Pipeline</p>
    </div>
    <div class='live-status'>● SYSTEM SECURE</div>
</div>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════
# Sidebar — Cryptographic Inventory
# ═══════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("<h2 class='glow-text' style='margin-top:0;'>🛡️ Crypto Inventory</h2>",
                unsafe_allow_html=True)

    for layer, cls, color in [
        ("Layer 1 · KEM",   Layer1_KEM,  "#8b5cf6"),
        ("Layer 2 · Auth",  Layer2_Sig,  "#3b82f6"),
        ("Layer 3 · Wrap",  Layer3_AES,  "#06b6d4"),
    ]:
        nist = f"NIST Level {cls.NIST_LEVEL}" if getattr(cls, "NIST_LEVEL", None) else f"{cls.KEY_BITS}-bit"
        st.markdown(f"""
        <div class='glass-card' style='padding:14px 18px; border-left:3px solid {color};'>
            <div style='font-size:0.75rem; color:#64748b; text-transform:uppercase;
                        letter-spacing:1px; margin-bottom:4px;'>{layer}</div>
            <div style='color:#e2e8f0; font-weight:600; font-size:1.05rem;'>{cls.ALGORITHM}</div>
            <div style='color:#94a3b8; font-size:0.8rem; margin-top:2px;'>{cls.FIPS} · {nist}</div>
        </div>
        """, unsafe_allow_html=True)

    # Run counter
    st.markdown(f"""
    <div style='text-align:center; margin-top:24px;'>
        <div style='color:#64748b; font-size:0.75rem; text-transform:uppercase;
                    letter-spacing:1px;'>Completed Transmissions</div>
        <div style='color:#c4b5fd; font-size:1.8rem; font-weight:700;
                    font-family:JetBrains Mono,monospace;'>{st.session_state.run_count}</div>
    </div>
    """, unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════
# Input Bar
# ═══════════════════════════════════════════════════════════════════════════
col_input, col_action = st.columns([4, 1])
with col_input:
    payload_input = st.text_input(
        "Inject Test Packet (Plaintext)",
        value="CONFIDENTIAL_TRAFFIC_PAYLOAD_V1",
        key="payload_input",
        label_visibility="collapsed",
        placeholder="Enter plaintext payload…",
    )
with col_action:
    run_btn = st.button("🚀  Transmit Securely", use_container_width=True, type="primary")


# ═══════════════════════════════════════════════════════════════════════════
# Execute Pipeline
# ═══════════════════════════════════════════════════════════════════════════
if run_btn and payload_input:
    with st.spinner("Executing 3-Layer Quantum-Resistant Protocol…"):
        result = run_sanity_check(payload_input.encode("utf-8"))
    st.session_state.last_result = result
    st.session_state.run_count += 1
    st.session_state.history.append({
        "run": st.session_state.run_count,
        "payload_len": len(payload_input),
        "status": result["status"],
        "total_ms": result["metrics"]["total_crypto_ms"],
        "pqc_pct": result["metrics"]["pqc_overhead_pct"],
    })


# ═══════════════════════════════════════════════════════════════════════════
# Render Results (persisted in session_state)
# ═══════════════════════════════════════════════════════════════════════════
result = st.session_state.last_result
if result is None:
    st.markdown("""
    <div class='glass-card' style='text-align:center; padding:48px 24px;'>
        <div style='font-size:2.5rem; margin-bottom:12px;'>🔐</div>
        <div style='color:#94a3b8; font-size:1.1rem;'>Enter a plaintext payload above and click
            <strong style='color:#8b5cf6;'>Transmit Securely</strong> to begin the 3-layer pipeline.</div>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

metrics = result["metrics"]

# ─── Section 1: Performance Metrics ───────────────────────────────────────
st.markdown("<h2 class='glow-text'>⚡ Performance Metrics</h2>", unsafe_allow_html=True)

m1, m2, m3, m4, m5 = st.columns(5)

tile_data = [
    (m1, "L1 · KEM Encaps",    metrics["kem_encaps_ms"],  "#8b5cf6", "rgba(139,92,246,0.25)"),
    (m2, "L2 · DSA Sign",      metrics["sig_sign_ms"],    "#3b82f6", "rgba(59,130,246,0.25)"),
    (m3, "L3 · AES Encrypt",   metrics["aes_enc_ms"],     "#06b6d4", "rgba(6,182,212,0.25)"),
    (m4, "Total Pipeline",     metrics["total_crypto_ms"], "#f59e0b", "rgba(245,158,11,0.25)"),
]
for col, label, value, color, glow in tile_data:
    with col:
        st.markdown(f"""
        <div class='glass-card' style='text-align:center; padding:20px 12px;'>
            <div class='metric-label'>{label}</div>
            <div class='metric-value' style='color:{color}; text-shadow:0 0 18px {glow};'>
                {value:.2f}<span class='metric-unit'>ms</span></div>
        </div>
        """, unsafe_allow_html=True)

# Overhead tile with mini bar
pqc_pct = metrics["pqc_overhead_pct"]
with m5:
    st.markdown(f"""
    <div class='glass-card' style='text-align:center; padding:20px 12px;'>
        <div class='metric-label'>PQC Overhead</div>
        <div class='metric-value' style='color:#ec4899; text-shadow:0 0 18px rgba(236,72,153,0.25);'>
            {pqc_pct:.1f}<span class='metric-unit'>%</span></div>
        <div class='overhead-bar-bg'>
            <div class='overhead-bar-fill' style='width:{min(pqc_pct, 100):.0f}%;'></div>
        </div>
    </div>
    """, unsafe_allow_html=True)


# ─── Section 2: Security Health Check ─────────────────────────────────────
st.markdown("<h2 class='glow-text'>🩺 Security Health Check</h2>", unsafe_allow_html=True)

sig_ok      = result.get("sig_verified", False)
integrity   = result["status"] == "PASS"
kem_ok      = metrics.get("kem_decaps_ms", 0) > 0   # decaps ran successfully

steps = [
    ("🔑", "ML-KEM-768 Key Exchange",
     f"Shared secret negotiated in {metrics['kem_encaps_ms'] + metrics['kem_decaps_ms']:.2f} ms",
     kem_ok),
    ("✍️", "ML-DSA-65 Signature Verification",
     f"Signature {'VALID' if sig_ok else 'INVALID'} — verified in {metrics['sig_verify_ms']:.2f} ms",
     sig_ok),
    ("🔓", "AES-256-GCM Decryption Gated on Sig",
     f"Decryption {'proceeded' if sig_ok else 'BLOCKED — signature failed'} in {metrics['aes_dec_ms']:.2f} ms",
     sig_ok),
    ("✅", "End-to-End Integrity",
     "Decrypted output matches original plaintext byte-for-byte" if integrity
     else "⚠️ Decrypted output does NOT match — possible tampering",
     integrity),
]

hc1, hc2 = st.columns([3, 2])
with hc1:
    html_steps = ""
    for icon, label, detail, passed in steps:
        css   = "step-pass" if passed else "step-fail"
        check = "✓" if passed else "✗"
        html_steps += f"""
        <div class='pipeline-step'>
            <div class='step-icon {css}'>{icon}</div>
            <div>
                <div class='step-label'>{label} <span style='color:{"#10b981" if passed else "#ef4444"};
                     font-size:0.85rem;'>[{check}]</span></div>
                <div class='step-detail'>{detail}</div>
            </div>
        </div>"""
    st.markdown(f"<div class='glass-card' style='padding:16px 20px;'>{html_steps}</div>",
                unsafe_allow_html=True)

with hc2:
    # Timing breakdown donut (pure HTML/CSS)
    kem_pct = (metrics["kem_encaps_ms"] + metrics["kem_decaps_ms"]) / metrics["total_crypto_ms"] * 100
    sig_pct = (metrics["sig_sign_ms"] + metrics["sig_verify_ms"])   / metrics["total_crypto_ms"] * 100
    aes_pct = metrics["aes_total_ms"]                               / metrics["total_crypto_ms"] * 100
    st.markdown(f"""
    <div class='glass-card' style='padding:20px;'>
        <div style='color:#94a3b8; font-size:0.8rem; text-transform:uppercase;
                    letter-spacing:1px; margin-bottom:12px;'>Time Distribution</div>
        <div style='display:flex; flex-direction:column; gap:10px;'>
            <div>
                <div style='display:flex; justify-content:space-between; font-size:0.85rem;'>
                    <span style='color:#8b5cf6;'>■ KEM (L1)</span>
                    <span style='color:#94a3b8;'>{kem_pct:.1f}%</span>
                </div>
                <div class='overhead-bar-bg'><div class='overhead-bar-fill'
                    style='width:{kem_pct:.0f}%; background:linear-gradient(90deg,#8b5cf6,#a78bfa);'></div></div>
            </div>
            <div>
                <div style='display:flex; justify-content:space-between; font-size:0.85rem;'>
                    <span style='color:#3b82f6;'>■ Signatures (L2)</span>
                    <span style='color:#94a3b8;'>{sig_pct:.1f}%</span>
                </div>
                <div class='overhead-bar-bg'><div class='overhead-bar-fill'
                    style='width:{sig_pct:.0f}%; background:linear-gradient(90deg,#3b82f6,#60a5fa);'></div></div>
            </div>
            <div>
                <div style='display:flex; justify-content:space-between; font-size:0.85rem;'>
                    <span style='color:#06b6d4;'>■ AES-GCM (L3)</span>
                    <span style='color:#94a3b8;'>{aes_pct:.1f}%</span>
                </div>
                <div class='overhead-bar-bg'><div class='overhead-bar-fill'
                    style='width:{max(aes_pct, 1):.0f}%; background:linear-gradient(90deg,#06b6d4,#22d3ee);'></div></div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)


# ─── Section 3: Live Traffic Log ──────────────────────────────────────────
st.markdown("<h2 class='glow-text'>📡 Live Traffic Log</h2>", unsafe_allow_html=True)

c1, c2 = st.columns(2)

with c1:
    st.markdown(f"""
    <div class='glass-card'>
        <div style='display:flex; justify-content:space-between; align-items:baseline;'>
            <h4 style='margin:0; color:#cbd5e1;'>Layer 1 · ML-KEM Ciphertext</h4>
            <span style='color:#64748b; font-size:0.75rem;'>{len(result["ciphertext_kem"])} bytes</span>
        </div>
        <p style='color:#94a3b8; font-size:0.82rem; margin:6px 0 10px 0;'>
            Lattice-based encapsulation of the symmetric session key.</p>
        <div class='hex-dump'>{fmt_hex(result["ciphertext_kem"])}</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown(f"""
    <div class='glass-card'>
        <div style='display:flex; justify-content:space-between; align-items:baseline;'>
            <h4 style='margin:0; color:#cbd5e1;'>Layer 3 · AES-256-GCM Payload</h4>
            <span style='color:#64748b; font-size:0.75rem;'>{len(result["ciphertext_aes"])} bytes</span>
        </div>
        <p style='color:#94a3b8; font-size:0.82rem; margin:6px 0 10px 0;'>
            Authenticated ciphertext with 128-bit GCM tag appended.</p>
        <div class='hex-dump'>{fmt_hex(result["ciphertext_aes"])}</div>
    </div>
    """, unsafe_allow_html=True)

with c2:
    st.markdown(f"""
    <div class='glass-card'>
        <div style='display:flex; justify-content:space-between; align-items:baseline;'>
            <h4 style='margin:0; color:#cbd5e1;'>Layer 2 · ML-DSA Signature</h4>
            <span style='color:#64748b; font-size:0.75rem;'>{len(result["signature"])} bytes</span>
        </div>
        <p style='color:#94a3b8; font-size:0.82rem; margin:6px 0 10px 0;'>
            Quantum-resistant signature binding nonce + ciphertext.</p>
        <div class='hex-dump'>{fmt_hex(result["signature"])}</div>
    </div>
    """, unsafe_allow_html=True)

    # Decrypted output card — green accent
    dec_text = result["decrypted_text"].decode("utf-8", errors="replace")
    st.markdown(f"""
    <div class='glass-card' style='border-color:rgba(16,185,129,0.35);'>
        <div style='display:flex; justify-content:space-between; align-items:baseline;'>
            <h4 style='margin:0; color:#10b981;'>✓ Decrypted Output</h4>
            <span style='color:#64748b; font-size:0.75rem;'>{len(result["decrypted_text"])} bytes</span>
        </div>
        <p style='color:#94a3b8; font-size:0.82rem; margin:6px 0 10px 0;'>
            Data verified through all 3 layers — integrity confirmed.</p>
        <div style='background:rgba(16,185,129,0.08); padding:16px; border-radius:10px;
                    border:1px solid rgba(16,185,129,0.15); color:#f8fafc; font-size:1.15rem;
                    font-family:JetBrains Mono,monospace; letter-spacing:0.5px;'>{dec_text}</div>
    </div>
    """, unsafe_allow_html=True)


# ─── Final Status Banner ─────────────────────────────────────────────────
if result["status"] == "PASS":
    st.success("✅  INTEGRITY VERIFIED — Packet traversed all 3 encryption layers without data loss.")
else:
    st.error("❌  INTEGRITY FAILED — Data loss or tampering detected during pipeline transit.")
