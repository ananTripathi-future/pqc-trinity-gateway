import socket
import json
import base64
import time
from colorama import init, Fore, Style
from kyber_py.ml_kem import ML_KEM_768
from dilithium_py.ml_dsa import ML_DSA_65
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

init(autoreset=True)

def print_header():
    print(Fore.CYAN + "╔═══════════════════════════════════════════════════════╗")
    print(Fore.CYAN + "║   PQC Trinity Gateway — RECEIVER (Layer 1, 2, 3)    ║")
    print(Fore.CYAN + "╚═══════════════════════════════════════════════════════╝\n")

def start_receiver(host='127.0.0.1', port=65432):
    print_header()
    
    # 1. Generate ML-KEM-768 Keypair (Receiver's side for KEM)
    print(Fore.YELLOW + "[*] Initializing Layer 1: Generating ML-KEM-768 Keypair...")
    t0 = time.time()
    kem_pk, kem_sk = ML_KEM_768.keygen()
    print(Fore.GREEN + f"  ✓ ML-KEM-768 Keypair generated in {(time.time()-t0)*1000:.1f} ms")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(Fore.CYAN + f"\n[*] Listening for incoming PQC connections on {host}:{port}...")
        
        conn, addr = s.accept()
        with conn:
            print(Fore.GREEN + f"\n[+] Connection established from {addr}")
            
            # Send Receiver's ML-KEM public key to Transmitter
            kem_pk_b64 = base64.b64encode(kem_pk).decode('utf-8')
            conn.sendall(json.dumps({"kem_pk": kem_pk_b64}).encode('utf-8'))
            print(Fore.MAGENTA + "  -> Sent ML-KEM-768 Public Key to Transmitter")
            
            # Wait for encrypted payload from Transmitter
            data = b""
            while True:
                chunk = conn.recv(16384)
                if not chunk:
                    break
                data += chunk
                
            if not data:
                return
                
            print(Fore.YELLOW + "\n[*] Received encrypted transmission. Starting PQC Decryption Pipeline...")
            payload = json.loads(data.decode('utf-8'))
            
            kem_ct = base64.b64decode(payload['kem_ct'])
            nonce = base64.b64decode(payload['nonce'])
            aes_ct = base64.b64decode(payload['aes_ct'])
            signature = base64.b64decode(payload['signature'])
            dsa_pk = base64.b64decode(payload['dsa_pk'])
            
            # --- Layer 2: Signature Verification ---
            print(Fore.YELLOW + "\n[*] Layer 2: Verifying ML-DSA-65 Signature...")
            t0 = time.time()
            data_to_verify = nonce + aes_ct
            is_valid = ML_DSA_65.verify(dsa_pk, data_to_verify, signature)
            if is_valid:
                print(Fore.GREEN + f"  ✓ Signature VALID: Integrity confirmed in {(time.time()-t0)*1000:.1f} ms")
            else:
                print(Fore.RED + "  ✗ Signature INVALID: Tampering detected! Aborting.")
                return
                
            # --- Layer 1: KEM Decapsulation ---
            print(Fore.YELLOW + "\n[*] Layer 1: Decapsulating ML-KEM-768 Ciphertext...")
            t0 = time.time()
            shared_secret = ML_KEM_768.decaps(kem_sk, kem_ct)
            print(Fore.GREEN + f"  ✓ Shared secret recovered in {(time.time()-t0)*1000:.1f} ms")
            
            # --- Layer 3: AES-256-GCM Decryption ---
            print(Fore.YELLOW + "\n[*] Layer 3: Decrypting AES-256-GCM Payload...")
            t0 = time.time()
            aesgcm = AESGCM(shared_secret)
            plaintext = aesgcm.decrypt(nonce, aes_ct, None)
            print(Fore.GREEN + f"  ✓ Payload decrypted in {(time.time()-t0)*1000:.1f} ms")
            
            # --- Final Output ---
            print(Fore.CYAN + "\n" + "="*60)
            print(Fore.CYAN + "🎯 DECODED MESSAGE:")
            print(Style.BRIGHT + Fore.WHITE + f"\n{plaintext.decode('utf-8')}\n")
            print(Fore.CYAN + "="*60)

if __name__ == "__main__":
    start_receiver()
