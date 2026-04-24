import os
import json
import base64
import time
import shutil
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dilithium_py.ml_dsa import ML_DSA_65

DATA_DIR = "data"
ROOMS_DIR = "rooms"
USERS_FILE = os.path.join(DATA_DIR, "users.json")
INVITES_FILE = os.path.join(DATA_DIR, "invites.json")

for d in [DATA_DIR, ROOMS_DIR]:
    if not os.path.exists(d):
        os.makedirs(d)

# --- Authentication & Users ---

def _hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def register_user(username: str, password: str) -> bool:
    username = username.strip().lower()
    users = read_json(USERS_FILE) or {}
    if username in users:
        return False # Username taken
    users[username] = _hash_pw(password)
    write_json(USERS_FILE, users)
    return True

def login_user(username: str, password: str) -> bool:
    username = username.strip().lower()
    users = read_json(USERS_FILE) or {}
    if username not in users:
        return False
    return users[username] == _hash_pw(password)

def get_all_usernames() -> list:
    users = read_json(USERS_FILE) or {}
    return list(users.keys())

# --- Invites ---

def send_invite(from_user: str, to_user: str, room_code: str):
    to_user = to_user.strip().lower()
    invites = read_json(INVITES_FILE) or {}
    if to_user not in invites:
        invites[to_user] = []
    
    # Store invite as dict
    invite = {"from": from_user, "room": room_code, "timestamp": time.time()}
    invites[to_user].append(invite)
    write_json(INVITES_FILE, invites)

def get_invites(username: str) -> list:
    username = username.strip().lower()
    invites = read_json(INVITES_FILE) or {}
    return invites.get(username, [])

def clear_invite(username: str, room_code: str):
    username = username.strip().lower()
    invites = read_json(INVITES_FILE) or {}
    if username in invites:
        invites[username] = [inv for inv in invites[username] if inv["room"] != room_code]
        write_json(INVITES_FILE, invites)

# --- File System Routing ---

def get_room_path(room_code: str) -> str:
    return os.path.join(ROOMS_DIR, room_code)

def delete_room(room_code: str):
    path = get_room_path(room_code)
    if os.path.exists(path):
        try:
            shutil.rmtree(path)
        except:
            pass

def read_json(path: str):
    if not os.path.exists(path): return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return None

def write_json(path: str, data: dict):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)

def append_jsonl(path: str, data: dict):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(data) + "\n")

def read_jsonl(path: str):
    if not os.path.exists(path): return []
    res = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try: res.append(json.loads(line))
                except: pass
    return res

# --- Cryptography Pipeline ---

def encrypt_message(shared_secret: bytes, sender_sk: tuple, payload: dict, sender_id: str) -> dict:
    t0 = time.time()
    aesgcm = AESGCM(shared_secret)
    nonce = os.urandom(12)
    
    # Convert payload dict to bytes
    payload_bytes = json.dumps(payload).encode('utf-8')
    aes_ct = aesgcm.encrypt(nonce, payload_bytes, None)
    
    data_to_sign = nonce + aes_ct
    signature = ML_DSA_65.sign(sender_sk, data_to_sign)
    
    return {
        "sender": sender_id,
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "aes_ct": base64.b64encode(aes_ct).decode('utf-8'),
        "signature": base64.b64encode(signature).decode('utf-8'),
        "timestamp": time.time(),
        "crypto_ms": (time.time() - t0) * 1000,
        "aes_len": len(aes_ct),
        "sig_len": len(signature)
    }

def decrypt_message(shared_secret: bytes, sender_pk: bytes, packet: dict) -> dict:
    t0 = time.time()
    try:
        nonce = base64.b64decode(packet["nonce"])
        aes_ct = base64.b64decode(packet["aes_ct"])
        signature = base64.b64decode(packet["signature"])
        
        data_to_verify = nonce + aes_ct
        is_valid = ML_DSA_65.verify(sender_pk, data_to_verify, signature)
        
        if not is_valid:
            return {"error": "Signature Verification Failed - Tampering Detected!"}
            
        aesgcm = AESGCM(shared_secret)
        plaintext_bytes = aesgcm.decrypt(nonce, aes_ct, None)
        
        try:
            payload = json.loads(plaintext_bytes.decode('utf-8'))
        except:
            # Fallback for old simple string payloads
            payload = {"type": "text", "text": plaintext_bytes.decode('utf-8', errors='replace')}
            
        return {
            "payload": payload,
            "crypto_ms": (time.time() - t0) * 1000,
            "is_valid": is_valid
        }
    except Exception as e:
        return {"error": f"Decryption error: {e}"}
