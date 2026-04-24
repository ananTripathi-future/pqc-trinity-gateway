"""
dashboard_tx.py — PQC Trinity Gateway: Transmitter (Host) Dashboard
"""

import streamlit as st
import time
import base64
import random
import os
from kyber_py.ml_kem import ML_KEM_768
from dilithium_py.ml_dsa import ML_DSA_65
from chat_core import (
    get_room_path, read_json, write_json, append_jsonl, read_jsonl, 
    encrypt_message, decrypt_message, register_user, login_user, 
    get_all_usernames, send_invite, delete_room
)

# ═══════════════════════════════════════════════════════════════════════════
# Page Config
# ═══════════════════════════════════════════════════════════════════════════
st.set_page_config(page_title="Transmitter - Host", page_icon="📡", layout="wide")

# ═══════════════════════════════════════════════════════════════════════════
# CSS — Premium Design System
# ═══════════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Outfit:wght@500;600;700;800&family=Fira+Code:wght@400;500&display=swap');
    html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
    h1, h2, h3, h4 { font-family: 'Outfit', sans-serif !important; }
    .stApp { background: radial-gradient(circle at top right, #0f172a 0%, #020617 100%); color: #f8fafc; }
    
    .glass-card { 
        background: rgba(30, 41, 59, 0.4); backdrop-filter: blur(16px); 
        border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 24px; 
        padding: 32px; margin-bottom: 24px; 
        box-shadow: 0 10px 40px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255,255,255,0.1); 
        transition: transform 0.3s ease, border-color 0.3s ease;
    }
    .glass-card:hover { border-color: rgba(139, 92, 246, 0.4); transform: translateY(-2px); }
    
    .glow-text { background: linear-gradient(135deg, #8b5cf6 0%, #3b82f6 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-weight: 800; }
    
    .status-badge { display: inline-block; padding: 6px 14px; border-radius: 30px; font-size: 0.75rem; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; }
    .status-green { background: rgba(16, 185, 129, 0.1); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); box-shadow: 0 0 15px rgba(16,185,129,0.2); }
    .status-blue { background: rgba(56, 189, 248, 0.1); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); box-shadow: 0 0 15px rgba(56,189,248,0.2); }
    .status-red { background: rgba(239, 68, 68, 0.1); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); box-shadow: 0 0 15px rgba(239,68,68,0.2); }
    
    /* Chat layout */
    .msg-wrapper { display: flex; width: 100%; margin-bottom: 20px; }
    .msg-me { justify-content: flex-end; }
    .msg-them { justify-content: flex-start; }
    
    .chat-bubble { max-width: 75%; padding: 18px 24px; position: relative; box-shadow: 0 4px 20px rgba(0,0,0,0.25); }
    .chat-bubble-me { background: linear-gradient(135deg, #4f46e5 0%, #3b82f6 100%); border-radius: 24px 24px 6px 24px; color: white; border: 1px solid rgba(255,255,255,0.1); }
    .chat-bubble-them { background: rgba(30, 41, 59, 0.8); backdrop-filter: blur(8px); border: 1px solid rgba(255,255,255,0.1); border-radius: 24px 24px 24px 6px; color: #f8fafc; border-left: 3px solid #10b981; }
    .chat-bubble-tampered { background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.5); border-left: 3px solid #ef4444; color: #f8fafc; border-radius: 24px 24px 24px 6px; }
    
    .chat-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 8px; }
    .chat-user { font-weight: 700; display: flex; align-items: center; gap: 8px; font-size: 0.9rem; }
    .chat-crypto-status { font-family: 'Fira Code', monospace; font-size: 0.75rem; opacity: 0.85; background: rgba(0,0,0,0.2); padding: 2px 8px; border-radius: 10px; }
    .chat-body { font-size: 1.05rem; line-height: 1.6; }
    
    .room-code-box { background: rgba(0,0,0,0.3); padding: 30px; border-radius: 20px; border: 1px dashed rgba(56, 189, 248, 0.5); margin: 20px 0; }
    .room-code { font-family: 'Fira Code', monospace; font-size: 4rem; color: #38bdf8; text-shadow: 0 0 20px rgba(56, 189, 248, 0.5); text-align: center; letter-spacing: 8px; font-weight: 800; line-height: 1; }
    
    /* Streamlit Button & Input Overrides */
    [data-testid="baseButton-primary"] {
        background: linear-gradient(135deg, #8b5cf6 0%, #3b82f6 100%) !important;
        border: none !important;
        color: white !important;
        border-radius: 12px !important;
        font-weight: 600 !important;
        box-shadow: 0 4px 15px rgba(59, 130, 246, 0.4) !important;
        transition: all 0.3s ease !important;
    }
    [data-testid="baseButton-primary"]:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 6px 20px rgba(139, 92, 246, 0.6) !important;
        filter: brightness(1.1) !important;
    }
    [data-testid="baseButton-secondary"] {
        background: rgba(30, 41, 59, 0.6) !important;
        border: 1px solid rgba(139, 92, 246, 0.5) !important;
        color: #e2e8f0 !important;
        border-radius: 12px !important;
        font-weight: 500 !important;
        transition: all 0.3s ease !important;
    }
    [data-testid="baseButton-secondary"]:hover {
        background: rgba(139, 92, 246, 0.2) !important;
        border-color: #8b5cf6 !important;
        transform: translateY(-2px) !important;
        box-shadow: 0 4px 15px rgba(139, 92, 246, 0.3) !important;
        color: white !important;
    }
    .stTextInput input {
        background: rgba(15, 23, 42, 0.6) !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        color: white !important;
        border-radius: 10px !important;
        padding: 12px !important;
    }
    .stTextInput input:focus {
        border-color: #8b5cf6 !important;
        box-shadow: 0 0 10px rgba(139, 92, 246, 0.3) !important;
    }
</style>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════
# Session State & Logic
# ═══════════════════════════════════════════════════════════════════════════
if "username" not in st.session_state:
    st.session_state.username = None
if "room_code" not in st.session_state:
    st.session_state.room_code = None
if "dsa_keys" not in st.session_state:
    st.session_state.dsa_keys = ML_DSA_65.keygen()
if "shared_secret" not in st.session_state:
    st.session_state.shared_secret = None
if "peer_dsa_pk" not in st.session_state:
    st.session_state.peer_dsa_pk = None

# --- AUTHENTICATION ---
if not st.session_state.username:
    st.markdown("<div style='text-align:center; margin-bottom:40px;'><h1 class='glow-text' style='font-size:3.5rem;'>PQC Trinity Gateway</h1><div class='status-badge status-blue'>Transmitter Terminal (Host)</div></div>", unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Login")
        l_user = st.text_input("Username", key="l_user")
        l_pass = st.text_input("Password", type="password", key="l_pass")
        if st.button("Login", use_container_width=True):
            if login_user(l_user, l_pass):
                st.session_state.username = l_user.lower()
                st.rerun()
            else:
                st.error("Invalid credentials.")
        
    with col2:
        st.subheader("Register")
        r_user = st.text_input("New Username", key="r_user")
        r_pass = st.text_input("New Password", type="password", key="r_pass")
        if st.button("Register", use_container_width=True):
            if r_user and r_pass:
                if register_user(r_user, r_pass):
                    st.success("Registered successfully! You can now log in.")
                else:
                    st.error("Username already taken.")
            else:
                st.warning("Please fill all fields.")
    st.stop()


# Main Header
st.markdown(f"""
<div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:2rem;'>
    <div>
        <h1 style='margin:0; background:-webkit-linear-gradient(45deg,#8b5cf6,#3b82f6); -webkit-background-clip:text; -webkit-text-fill-color:transparent;'>Transmitter (Host)</h1>
        <p style='color:#94a3b8; margin:0;'>Logged in as: <strong>@{st.session_state.username}</strong></p>
    </div>
</div>
""", unsafe_allow_html=True)

# --- State 1: No Room Created ---
if not st.session_state.room_code:
    st.markdown("<div class='glass-card' style='text-align:center;'>", unsafe_allow_html=True)
    st.markdown("<h3>Create a Secure Quantum-Resistant Room</h3>", unsafe_allow_html=True)
    if st.button("Generate Room Code", type="primary", use_container_width=True):
        code = str(random.randint(100000, 999999))
        st.session_state.room_code = code
        path = get_room_path(code)
        os.makedirs(path, exist_ok=True)
        write_json(os.path.join(path, "tx_pubkeys.json"), {
            "dsa_pk": base64.b64encode(st.session_state.dsa_keys[0]).decode('utf-8')
        })
        st.rerun()
    st.markdown("</div>", unsafe_allow_html=True)
    st.stop()

code = st.session_state.room_code
path = get_room_path(code)

# Ensure room exists
if not os.path.exists(path):
    st.error("Room was deleted.")
    st.session_state.room_code = None
    st.session_state.shared_secret = None
    if st.button("Back to Home"): st.rerun()
    st.stop()


# --- Sidebar Actions ---
with st.sidebar:
    st.markdown("### Room Actions")
    st.info(f"Current Room: {code}")
    
    with st.expander("Invite User"):
        invite_user = st.text_input("Username to invite:")
        if st.button("Send Invite"):
            send_invite(st.session_state.username, invite_user, code)
            st.success("Invite sent!")
            
    st.markdown("---")
    if st.button("🚪 Leave & Destroy Room", type="primary"):
        st.session_state.confirm_leave = True
        st.rerun()
        
    if st.session_state.get("confirm_leave"):
        st.warning("Are you sure? This will instantly destroy the room and wipe all history for all users.")
        col1, col2 = st.columns(2)
        if col1.button("Confirm Destroy"):
            delete_room(code)
            st.session_state.room_code = None
            st.session_state.shared_secret = None
            st.session_state.confirm_leave = False
            st.rerun()
        if col2.button("Cancel"):
            st.session_state.confirm_leave = False
            st.rerun()


# --- State 2: Waiting for Receiver & Handshake ---
if st.session_state.shared_secret is None:
    st.markdown(f"<div class='glass-card'><div style='text-align:center;'><p style='color:#94a3b8; text-transform:uppercase;'>Room Code</p><div class='room-code'>{code}</div><p style='color:#f59e0b; margin-top:10px;'>Waiting for Receiver to join...</p></div></div>", unsafe_allow_html=True)
    
    rx_keys = read_json(os.path.join(path, "rx_pubkeys.json"))
    if rx_keys:
        st.info("Receiver connected! Performing KEM Encapsulation...")
        kem_pk = base64.b64decode(rx_keys["kem_pk"])
        peer_dsa_pk = base64.b64decode(rx_keys["dsa_pk"])
        st.session_state.peer_dsa_pk = peer_dsa_pk
        
        shared_secret, kem_ct = ML_KEM_768.encaps(kem_pk)
        st.session_state.shared_secret = shared_secret
        
        write_json(os.path.join(path, "kem_exchange.json"), {
            "kem_ct": base64.b64encode(kem_ct).decode('utf-8')
        })
        st.rerun()
        
    time.sleep(1)
    st.rerun()

# --- State 3: Chat Interface ---
st.success(f"🔐 Secure line established!")

if os.path.exists(os.path.join(path, "jam.flag")):
    st.error("⚠️ SECURE LINE INTERCEPTED / JAMMED BY ATTACKER. TRANSMISSION BLOCKED.")
    is_jammed = True
else:
    is_jammed = False

messages_path = os.path.join(path, "messages.jsonl")
messages = read_jsonl(messages_path)

st.markdown("<div class='glass-card' style='height: 500px; overflow-y: auto; padding: 20px;'><div class='chat-container'>", unsafe_allow_html=True)
for msg in messages:
    sender_id = msg["sender"]
    is_me = (sender_id == st.session_state.username)
    
    # Decrypt
    dec = decrypt_message(
        st.session_state.shared_secret, 
        st.session_state.dsa_keys[0] if is_me else st.session_state.peer_dsa_pk, 
        msg
    )
    
    wrapper_cls = "msg-me" if is_me else "msg-them"
    bubble_cls = "chat-bubble-me" if is_me else "chat-bubble-them"
    
    if "error" in dec:
        st.markdown(f"<div class='msg-wrapper {wrapper_cls}'><div class='chat-bubble chat-bubble-tampered'><div class='chat-header'><span class='chat-user'>⚠️ {sender_id} [TAMPERED]</span></div><div class='chat-body'>❌ {dec['error']}</div></div></div>", unsafe_allow_html=True)
        continue
        
    payload = dec["payload"]
    status_icon = "✓ VALID" if dec.get("is_valid") else "⚠️ INVALID"
    status_color = "#10b981" if dec.get("is_valid") else "#ef4444"
    
    # Calculate Latency
    enc_lat = msg.get("crypto_ms", 0)
    dec_lat = dec.get("crypto_ms", 0)
    total_lat = enc_lat + dec_lat
    
    st.markdown(f"<div class='msg-wrapper {wrapper_cls}'><div class='chat-bubble {bubble_cls}'>", unsafe_allow_html=True)
    st.markdown(f"<div class='chat-header'><span class='chat-user'>👤 @{sender_id}</span><div><span class='chat-crypto-status' style='color:#a855f7; margin-right: 5px;'>⏱️ {total_lat:.1f}ms</span><span class='chat-crypto-status' style='color:{status_color};'>ML-DSA {status_icon}</span></div></div>", unsafe_allow_html=True)
    
    st.markdown("<div class='chat-body'>", unsafe_allow_html=True)
    if payload.get("type") == "text":
        st.write(payload.get("text", ""))
    elif payload.get("type") == "file":
        st.write(f"📎 **File Attached:** `{payload.get('filename')}`")
        file_data = base64.b64decode(payload.get('data_b64', ''))
        st.download_button("⬇️ Download Secure File", data=file_data, file_name=payload.get('filename'), key=f"dl_{msg['timestamp']}")
    st.markdown("</div></div></div>", unsafe_allow_html=True)

st.markdown("</div></div>", unsafe_allow_html=True)

# Input Box
if not is_jammed:
    st.markdown("#### Secure Compose")
    col_text, col_file = st.columns([3, 1])
    
    with col_text:
        with st.form("chat_form", clear_on_submit=True):
            user_input = st.text_input("Message", placeholder="Enter confidential message...")
            submitted = st.form_submit_button("Send Text 🚀")
            if submitted and user_input:
                payload = {"type": "text", "text": user_input}
                packet = encrypt_message(st.session_state.shared_secret, st.session_state.dsa_keys[1], payload, st.session_state.username)
                append_jsonl(messages_path, packet)
                st.rerun()
                
    with col_file:
        with st.form("file_form", clear_on_submit=True):
            uploaded_file = st.file_uploader("Attach File", label_visibility="collapsed")
            file_submit = st.form_submit_button("Send File 📎")
            if file_submit and uploaded_file:
                b64_data = base64.b64encode(uploaded_file.read()).decode('utf-8')
                payload = {
                    "type": "file",
                    "filename": uploaded_file.name,
                    "data_b64": b64_data
                }
                packet = encrypt_message(st.session_state.shared_secret, st.session_state.dsa_keys[1], payload, st.session_state.username)
                append_jsonl(messages_path, packet)
                st.rerun()

time.sleep(1.5)
st.rerun()
