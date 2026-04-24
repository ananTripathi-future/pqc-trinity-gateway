import socket
import json
import base64
import time
import os
from colorama import init, Fore, Style
from kyber_py.ml_kem import ML_KEM_768
from dilithium_py.ml_dsa import ML_DSA_65
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

init(autoreset=True)

def print_header():
    print(Fore.CYAN + "╔═══════════════════════════════════════════════════════╗")
    print(Fore.CYAN + "║   PQC Trinity Gateway — TRANSMITTER (Layer 1, 2, 3) ║")
    print(Fore.CYAN + "╚═══════════════════════════════════════════════════════╝\n")

def start_transmitter(host='127.0.0.1', port=65432):
    print_header()
    
    # 1. Generate ML-DSA-65 Keypair (Transmitter's side for Auth)
    print(Fore.YELLOW + "[*] Initializing Layer 2: Generating ML-DSA-65 Host Keys...")
    t0 = time.time()
    dsa_pk, dsa_sk = ML_DSA_65.keygen()
    print(Fore.GREEN + f"  ✓ ML-DSA-65 Keypair generated in {(time.time()-t0)*1000:.1f} ms\n")
    
    message = input(Style.BRIGHT + Fore.WHITE + "Enter message to securely transmit: ")
    plaintext = message.encode('utf-8')
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(Fore.CYAN + f"\n[*] Connecting to Receiver at {host}:{port}...")
        try:
            s.connect((host, port))
        except ConnectionRefusedError:
            print(Fore.RED + "  ✗ Connection refused. Make sure the Receiver is running.")
            return
            
        print(Fore.GREEN + "  ✓ Connected.")
        
        # Receive Receiver's ML-KEM public key
        data = s.recv(16384)
        kem_pk_b64 = json.loads(data.decode('utf-8'))['kem_pk']
        kem_pk = base64.b64decode(kem_pk_b64)
        print(Fore.MAGENTA + "  <- Received ML-KEM-768 Public Key from Receiver")
        
        print(Fore.YELLOW + "\n[*] Starting PQC Encryption Pipeline...")
        
        # --- Layer 1: KEM Encapsulation ---
        print(Fore.YELLOW + "[*] Layer 1: Encapsulating symmetric key with ML-KEM-768...")
        t0 = time.time()
        shared_secret, kem_ct = ML_KEM_768.encaps(kem_pk)
        print(Fore.GREEN + f"  ✓ Shared secret encapsulated in {(time.time()-t0)*1000:.1f} ms")
        
        # --- Layer 3: AES-256-GCM Encryption ---
        print(Fore.YELLOW + "[*] Layer 3: Encrypting Payload with AES-256-GCM...")
        t0 = time.time()
        aesgcm = AESGCM(shared_secret)
        nonce = os.urandom(12)
        aes_ct = aesgcm.encrypt(nonce, plaintext, None)
        print(Fore.GREEN + f"  ✓ Payload encrypted in {(time.time()-t0)*1000:.1f} ms")
        
        # --- Layer 2: ML-DSA-65 Signature ---
        print(Fore.YELLOW + "[*] Layer 2: Signing payload with ML-DSA-65...")
        t0 = time.time()
        data_to_sign = nonce + aes_ct
        signature = ML_DSA_65.sign(dsa_sk, data_to_sign)
        print(Fore.GREEN + f"  ✓ Signature generated in {(time.time()-t0)*1000:.1f} ms")
        
        # Transmit bundle
        print(Fore.CYAN + "\n[*] Transmitting Secure Bundle to Receiver...")
        payload = {
            "kem_ct": base64.b64encode(kem_ct).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "aes_ct": base64.b64encode(aes_ct).decode('utf-8'),
            "signature": base64.b64encode(signature).decode('utf-8'),
            "dsa_pk": base64.b64encode(dsa_pk).decode('utf-8')
        }
        
        s.sendall(json.dumps(payload).encode('utf-8'))
        print(Fore.GREEN + "  ✓ Transmission Complete.")

if __name__ == "__main__":
    start_transmitter()
