<p align="center">
  <img src="https://img.shields.io/badge/FIPS_203-ML--KEM--768-8b5cf6?style=for-the-badge" alt="ML-KEM-768"/>
  <img src="https://img.shields.io/badge/FIPS_204-ML--DSA--65-3b82f6?style=for-the-badge" alt="ML-DSA-65"/>
  <img src="https://img.shields.io/badge/AES--256--GCM-Symmetric-06b6d4?style=for-the-badge" alt="AES-256-GCM"/>
  <img src="https://img.shields.io/badge/NIST-Post--Quantum_Ready-10b981?style=for-the-badge" alt="Post-Quantum"/>
</p>

# 🛡️ PQC Trinity Gateway

**A 3-Layer Post-Quantum Cryptographic Secure Gateway in C**

A unified Linux daemon that simultaneously secures three independent network protocol layers using NIST-standardized post-quantum cryptographic algorithms — protecting against Harvest Now, Decrypt Later attacks **today**.

> *"If a quantum computer turns on tomorrow morning, data flowing through this gateway is still secure."*

---

## 🏗️ Architecture — The Trinity

| Layer | Protocol | PQC Algorithm | Standard | Port |
|-------|----------|--------------|----------|------|
| **Layer 1 — Network** | IPsec (IKEv2 + ESP) | ML-KEM-768 (Hybrid) | FIPS 203 | strongSwan |
| **Layer 2 — Transport** | TLS 1.3 | X25519MLKEM768 | FIPS 203 | 8443 |
| **Layer 3 — Management** | SSH 2.0 | ML-DSA-65 Host Keys | FIPS 204 | 2222 |

```
                    ┌─────────────────────────────────────┐
                    │       PQC TRINITY GATEWAY            │
                    │                                       │
    IP Traffic ───► │  Layer 1: IPsec + ML-KEM-768         │
                    │    ├─ IKEv2 hybrid key exchange       │
                    │    └─ ESP tunnel with AES-256-GCM     │
                    │                                       │
   HTTPS Req  ───► │  Layer 2: TLS 1.3 + X25519MLKEM768   │
                    │    ├─ Enforced PQC group (no fallback)│
                    │    └─ PSK/0-RTT disabled              │
                    │                                       │
    SSH Login ───► │  Layer 3: SSH + ML-DSA-65             │
                    │    ├─ PQC host key on port 2222       │
                    │    └─ Ed25519 on port 22 (legacy)     │
                    │                                       │
                    │  ┌─────────────────────────────────┐  │
                    │  │ Security Vault (mlock + canary)  │  │
                    │  │ HMAC-Chained Audit Log           │  │
                    │  │ Privilege Separation (setuid)    │  │
                    │  └─────────────────────────────────┘  │
                    └─────────────────────────────────────┘
```

---

## 📁 Project Structure

```
pqc-trinity-gateway/
├── CMakeLists.txt                    # Hardened C build system
├── build.sh                          # One-shot dependency build + compile
├── setup.sh                          # System package installer
├── README.md
│
├── src/
│   ├── main.c                        # Orchestrator (bind → drop privs → threads)
│   ├── gateway.h                     # Shared types, constants, config struct
│   │
│   ├── vault/
│   │   ├── vault.h                   # mlock + canary + mprotect vault
│   │   └── vault.c                   # OPENSSL_cleanse, guard pages
│   │
│   ├── audit/
│   │   ├── audit.h                   # HMAC-SHA-256 chained log format
│   │   └── audit.c                   # Tamper-evident binary log engine
│   │
│   ├── layer1_ipsec/
│   │   ├── ipsec_manager.h           # strongSwan VICI client
│   │   └── ipsec_manager.c           # Config gen + IKE event monitor
│   │
│   ├── layer2_tls/
│   │   ├── tls_server.h              # X25519MLKEM768 TLS 1.3 server
│   │   └── tls_server.c             # OpenSSL 3.2 + oqs-provider
│   │
│   └── layer3_ssh/
│       ├── ssh_server.h              # ML-DSA-65 SSH server
│       └── ssh_server.c              # libssh + PQC host key wrapper
│
├── config/
│   ├── gateway.conf                  # Runtime configuration
│   ├── openssl-pqc.cnf               # OpenSSL oqs-provider config
│   ├── strongswan.conf               # IKEv2 ML-KEM-768 proposals
│   └── ipsec.conf                    # IPsec connection definitions
│
├── keys/                             # Generated at build time (gitignored)
│   ├── tls_cert.pem
│   ├── tls_key.pem
│   ├── ssh_host_ed25519
│   ├── ssh_host_mldsa65
│   └── ssh_host_mldsa65.pub
│
└── tests/
    ├── test_layer1.sh                # IPsec ML-KEM-768 verification
    ├── test_layer2.sh                # TLS X25519MLKEM768 handshake test
    ├── test_layer3.sh                # SSH port 2222 connection test
    └── test_audit.sh                 # HMAC chain integrity verification
```

---

## 🚀 Quick Start

### Prerequisites

- **Ubuntu 22.04 LTS** or Debian 12
- **Root access** (for mlockall, port binding, privilege dropping)

### 1. System Setup

```bash
sudo bash setup.sh
```

### 2. Build Everything

```bash
sudo bash build.sh
```

This builds liboqs, OpenSSL 3.2.1, oqs-provider, generates PQC keys, and compiles the gateway.

### 3. Run

```bash
sudo ./build/pqc-gateway
```

### 4. Test

```bash
# In separate terminals:
bash tests/test_layer2.sh    # TLS handshake
bash tests/test_layer3.sh    # SSH connection
bash tests/test_audit.sh     # Audit chain integrity
```

---

## 🔒 Security Hardening

| Mechanism | Implementation | Threat Mitigated |
|-----------|---------------|------------------|
| **mlockall()** | All pages pinned in RAM | Swap/hibernation key extraction |
| **mprotect(PROT_NONE)** | Key pages inaccessible when idle | /proc/mem read attacks |
| **Canary guards** | Head/tail sentinels on all key buffers | Buffer overflow detection |
| **OPENSSL_cleanse()** | Volatile write + memory barrier | Compiler-elided zeroing |
| **PR_SET_DUMPABLE=0** | Core dumps disabled | Key material in crash dumps |
| **RLIMIT_CORE=0** | Belt-and-suspenders core dump prevention | Key leak via core files |
| **MADV_DONTDUMP** | Per-page dump exclusion | Selective crash dump leaks |
| **setuid/setgid** | Privilege drop after socket binding | Blast radius minimization |
| **HMAC-SHA-256 chain** | Each audit record chains to previous | Audit log tampering |
| **O_APPEND** | Append-only audit log writes | Log overwrite attacks |
| **flock()** | Concurrent write safety | Race condition in logging |

### Compiler Hardening Flags

```
-fstack-protector-strong    # Stack canaries
-fstack-clash-protection    # Prevent stack-to-heap pivots
-fcf-protection=full        # Forward-edge CFI (Intel CET)
-D_FORTIFY_SOURCE=2         # Bounds-checked libc wrappers
-pie                        # ASLR (Position-Independent Executable)
-Wl,-z,relro -Wl,-z,now    # Full RELRO (read-only GOT)
-Wl,-z,noexecstack          # NX stack
```

---

## 📊 PQC Algorithm Parameters

### ML-KEM-768 (FIPS 203) — Key Encapsulation

| Parameter | Value |
|-----------|-------|
| Public key | 1,184 bytes |
| Secret key | 2,400 bytes |
| Ciphertext | 1,088 bytes |
| Shared secret | 32 bytes |
| Security level | NIST Level 3 |
| Security notion | IND-CCA2 |

### ML-DSA-65 (FIPS 204) — Digital Signatures

| Parameter | Value |
|-----------|-------|
| Public key | 1,952 bytes |
| Secret key | 4,032 bytes |
| Signature | 3,309 bytes |
| Security level | NIST Level 3 |
| Security notion | EUF-CMA |

---

## 🗺️ Future Roadmap

- **seccomp-bpf** — syscall sandboxing to restrict gateway to only needed syscalls
- **TPM 2.0** — hardware root of trust for master secret storage
- **FIPS 206 ML-KEM-1024** — higher security level upgrade path
- **Web UI** — localhost:8080 dashboard showing live connection status

---

## 📝 License

This project is provided for educational and research purposes.

---

<p align="center">
  <sub>Built by <b>Ojas Sharma</b> & <b>Anant Tripathi</b> — B.Tech Data Science, SRM University</sub><br/>
  <sub><b>FIPS 203</b> ML-KEM-768 · <b>FIPS 204</b> ML-DSA-65 · <b>liboqs</b> · <b>OpenSSL 3.2</b> · <b>strongSwan</b> · <b>libssh</b></sub>
</p>
