"""
dashboard_spy.py — PQC Trinity Gateway: Interceptor (Spy) Dashboard
"""

import streamlit as st
import time
import base64
import os
import json
from chat_core import get_room_path, read_json, read_jsonl

# ═══════════════════════════════════════════════════════════════════════════
# Page Config
# ═══════════════════════════════════════════════════════════════════════════
st.set_page_config(page_title="Interceptor - Wiretap", page_icon="🕷️", layout="wide")

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
    html, body, [class*="css"] { font-family: 'Share Tech Mono', monospace; }
    .stApp { background: linear-gradient(135deg, #0a0a0a 0%, #200000 50%, #0a0a0a 100%); color: #ff3333; }
    .glass-card { background: rgba(255, 0, 0, 0.05); backdrop-filter: blur(5px); border: 1px solid rgba(255, 51, 51, 0.2); border-radius: 4px; padding: 24px; margin-bottom: 20px; box-shadow: 0 0 20px rgba(255, 0, 0, 0.1); }
    .glow-text { text-shadow: 0 0 10px rgba(255, 51, 51, 0.8); color: #ff3333; text-transform: uppercase; }
    .hex-dump { font-size: 0.8rem; line-height: 1.4; color: #ff6666; background: rgba(0, 0, 0, 0.8); padding: 14px; border: 1px solid #ff3333; border-radius: 4px; height: 120px; overflow-y: auto; overflow-wrap: break-word; }
    .alert-box { border: 1px solid #ffaa00; background: rgba(255, 170, 0, 0.1); color: #ffaa00; padding: 10px; margin-top: 10px; font-weight: bold; }
    .attack-btn { width: 100%; margin-bottom: 8px; }
</style>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════
# Session State
# ═══════════════════════════════════════════════════════════════════════════
if "room_code" not in st.session_state:
    st.session_state.room_code = None
if "attack_mode" not in st.session_state:
    st.session_state.attack_mode = False

st.markdown("""
<div style='text-align:center; margin-bottom:2rem;'>
    <h1 class='glow-text' style='font-size:3rem; margin:0;'>INTERCEPTOR TERMINAL</h1>
    <p style='color:#ff8888;'>ACTIVE THREAT CAPABILITIES ENABLED</p>
</div>
""", unsafe_allow_html=True)

# --- State 1: Target Selection ---
if not st.session_state.room_code:
    st.markdown("<div class='glass-card' style='text-align:center;'>", unsafe_allow_html=True)
    st.markdown("<h3 style='color:#ff3333;'>Select Target Session (Room Code)</h3>", unsafe_allow_html=True)
    
    with st.form("spy_form"):
        code_input = st.text_input("Target Code", placeholder="e.g. 123456")
        submitted = st.form_submit_button("Initiate Wiretap 🕷️")
        
        if submitted and code_input:
            path = get_room_path(code_input)
            if not os.path.exists(path):
                st.error("Session not found. Target offline.")
            else:
                st.session_state.room_code = code_input
                st.rerun()
    st.markdown("</div>", unsafe_allow_html=True)
    st.stop()

code = st.session_state.room_code
path = get_room_path(code)

if not os.path.exists(path):
    st.error("TARGET SESSION TERMINATED BY HOST. CONNECTION LOST.")
    st.session_state.room_code = None
    if st.button("Return"): st.rerun()
    st.stop()

st.markdown(f"<h3 class='glow-text'>📡 LIVE WIRETAP: ROOM {code}</h3>", unsafe_allow_html=True)

col1, col2 = st.columns([1, 1])

# Column 1: Key Exchange
with col1:
    st.markdown("<div class='glass-card'>", unsafe_allow_html=True)
    st.markdown("<h4 style='margin-top:0;'>PHASE 1: KEY EXCHANGE</h4>", unsafe_allow_html=True)
    kem_exch = read_json(os.path.join(path, "kem_exchange.json"))
    if kem_exch:
        raw_hex = base64.b64decode(kem_exch["kem_ct"]).hex().upper()
        spaced_hex = " ".join(raw_hex[i:i+4] for i in range(0, len(raw_hex), 4))
        st.markdown(f"<div class='hex-dump'>{spaced_hex}</div>", unsafe_allow_html=True)
    else:
        st.markdown("<div class='hex-dump' style='color:#666;'>WAITING FOR KEY EXCHANGE...</div>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

# Column 2: Attack Vectors
with col2:
    st.markdown("<div class='glass-card' style='height: 100%;'>", unsafe_allow_html=True)
    st.markdown("<h4 style='margin-top:0;'>ACTIVE ATTACK VECTORS</h4>", unsafe_allow_html=True)
    
    # 1. Steal Key
    if st.button("1. Steal Key (Shor's Algorithm)", use_container_width=True):
        st.session_state.attack_mode = True
        st.rerun()
        
    if st.session_state.attack_mode:
        with st.spinner("Deploying Grovers/Shor's algorithms against lattice structure..."):
            time.sleep(1.5)
        st.markdown("""
        <div class='alert-box'>
            CRITICAL FAILURE.<br/>
            > Module-LWE Problem irreducible.<br/>
            > DECRYPTION IMPOSSIBLE.
        </div>
        """, unsafe_allow_html=True)
        
    # 2. Jam Traffic
    jam_file = os.path.join(path, "jam.flag")
    is_jammed = os.path.exists(jam_file)
    jam_lbl = "2. Stop Jamming Signal" if is_jammed else "2. Transmit Jamming Signal"
    if st.button(jam_lbl, use_container_width=True):
        if is_jammed:
            os.remove(jam_file)
        else:
            with open(jam_file, "w") as f: f.write("JAM")
        st.rerun()
        
    messages_path = os.path.join(path, "messages.jsonl")
    
    # 3. Corrupt Package
    if st.button("3. Corrupt Last Package (Tamper)", use_container_width=True):
        messages = read_jsonl(messages_path)
        if messages:
            last = messages[-1]
            # Flip a character in signature
            sig = list(last["signature"])
            sig[10] = 'X' if sig[10] != 'X' else 'Y'
            last["signature"] = "".join(sig)
            
            # Rewrite
            with open(messages_path, "w", encoding="utf-8") as f:
                for m in messages:
                    f.write(json.dumps(m) + "\n")
            st.success("Package Tampered. ML-DSA verification will fail on Receiver.")
        else:
            st.warning("No packages to tamper.")
            
    # 4. Delete Package
    if st.button("4. Delete Last Package (Drop)", use_container_width=True):
        messages = read_jsonl(messages_path)
        if messages:
            messages.pop()
            with open(messages_path, "w", encoding="utf-8") as f:
                for m in messages:
                    f.write(json.dumps(m) + "\n")
            st.success("Package Dropped silently.")
        else:
            st.warning("No packages to drop.")
            
    st.markdown("</div>", unsafe_allow_html=True)

# Bottom: Message Feed
st.markdown("<div class='glass-card'>", unsafe_allow_html=True)
st.markdown("<h4 style='margin-top:0;'>PHASE 2: INTERCEPTED TRAFFIC FEED</h4>", unsafe_allow_html=True)
messages = read_jsonl(os.path.join(path, "messages.jsonl"))

if not messages:
    st.markdown("<p style='color:#666;'>NO TRAFFIC DETECTED...</p>", unsafe_allow_html=True)
else:
    for i, msg in enumerate(messages[::-1]): # Reverse to show newest first
        sender = msg["sender"]
        aes_ct = base64.b64decode(msg["aes_ct"]).hex().upper()
        sig = base64.b64decode(msg["signature"]).hex().upper()
        
        st.markdown(f"""
        <div style='border: 1px solid #440000; padding: 10px; margin-bottom: 10px;'>
            <div style='display:flex; justify-content:space-between; color:#ff8888; font-size:0.8rem; border-bottom:1px solid #440000; padding-bottom:4px; margin-bottom:8px;'>
                <span>SOURCE: {sender}</span>
                <span>PACKET ID: {len(messages)-1-i} | AES_CT: {msg.get("aes_len",0)}B | SIG: {msg.get("sig_len",0)}B</span>
            </div>
            <strong>AES-256-GCM Payload:</strong><br/>
            <div style='font-size:0.7rem; color:#ff6666; word-break:break-all; margin-bottom:5px;'>{aes_ct[:120]}...</div>
            <strong>ML-DSA-65 Signature:</strong><br/>
            <div style='font-size:0.7rem; color:#884444; word-break:break-all;'>{sig[:120]}...</div>
        </div>
        """, unsafe_allow_html=True)

st.markdown("</div>", unsafe_allow_html=True)

time.sleep(1.5)
st.rerun()
