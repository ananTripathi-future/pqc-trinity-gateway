#!/bin/bash
# ============================================================================
# build.sh — One-Shot Dependency Build + Compile Script
#
# Fully idempotent (safe to run multiple times). Builds all PQC dependencies
# from source and compiles the gateway binary.
#
# Dependencies built:
#   1. liboqs        — ML-KEM-768 + ML-DSA-65 (FIPS 203/204)
#   2. OpenSSL 3.2.1 — TLS 1.3 with PQC group support
#   3. oqs-provider  — X25519MLKEM768 OpenSSL provider
#   4. libssh        — SSHv2 server library
#
# Authors: Ojas Sharma & Anant Tripathi — SRM University
# ============================================================================
set -euo pipefail

INSTALL_PREFIX=/usr/local
OSSL_PREFIX=/usr/local/ossl-pqc
OQS_VERSION=0.10.1
OPENSSL_VERSION=3.2.1
LIBSSH_VERSION=0.10.4

echo "╔═══════════════════════════════════════════════════════╗"
echo "║   PQC Trinity Gateway — Build                       ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# ── 1. liboqs ─────────────────────────────────────────────────────────────────
echo "[1/7] Building liboqs ${OQS_VERSION}..."
if [ ! -f ${INSTALL_PREFIX}/lib/liboqs.so ]; then
    rm -rf /tmp/liboqs
    git clone --depth 1 --branch ${OQS_VERSION} \
        https://github.com/open-quantum-safe/liboqs /tmp/liboqs
    cmake -S /tmp/liboqs -B /tmp/liboqs/build \
        -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} \
        -DOQS_USE_OPENSSL=ON \
        -DBUILD_SHARED_LIBS=ON \
        -GNinja
    cmake --build /tmp/liboqs/build --parallel $(nproc)
    sudo cmake --install /tmp/liboqs/build
    sudo ldconfig
    echo "  ✓ liboqs installed to ${INSTALL_PREFIX}"
else
    echo "  ✓ liboqs already installed (skipping)"
fi

# ── 2. OpenSSL 3.2.1 ─────────────────────────────────────────────────────────
echo ""
echo "[2/7] Building OpenSSL ${OPENSSL_VERSION}..."
if [ ! -f ${OSSL_PREFIX}/bin/openssl ]; then
    rm -rf /tmp/openssl-build
    wget -q "https://github.com/openssl/openssl/archive/refs/tags/openssl-${OPENSSL_VERSION}.tar.gz" \
        -O /tmp/openssl.tar.gz
    mkdir -p /tmp/openssl-build
    tar -xf /tmp/openssl.tar.gz -C /tmp/openssl-build --strip-components=1
    cd /tmp/openssl-build
    ./Configure --prefix=${OSSL_PREFIX} --openssldir=${OSSL_PREFIX}/ssl \
        shared linux-x86_64
    make -j$(nproc)
    sudo make install_sw
    sudo ldconfig
    echo "  ✓ OpenSSL ${OPENSSL_VERSION} installed to ${OSSL_PREFIX}"
else
    echo "  ✓ OpenSSL ${OPENSSL_VERSION} already installed (skipping)"
fi

# ── 3. OQS Provider ──────────────────────────────────────────────────────────
echo ""
echo "[3/7] Building oqs-provider..."
if [ ! -f ${OSSL_PREFIX}/lib64/ossl-modules/oqsprovider.so ] && \
   [ ! -f ${OSSL_PREFIX}/lib/ossl-modules/oqsprovider.so ]; then
    rm -rf /tmp/oqs-provider
    git clone --depth 1 https://github.com/open-quantum-safe/oqs-provider /tmp/oqs-provider
    cmake -S /tmp/oqs-provider -B /tmp/oqs-provider/build \
        -DOPENSSL_ROOT_DIR=${OSSL_PREFIX} \
        -Dliboqs_DIR=${INSTALL_PREFIX}/lib/cmake/liboqs \
        -DCMAKE_INSTALL_PREFIX=${OSSL_PREFIX}
    cmake --build /tmp/oqs-provider/build --parallel $(nproc)
    sudo cmake --install /tmp/oqs-provider/build
    echo "  ✓ oqs-provider installed"
else
    echo "  ✓ oqs-provider already installed (skipping)"
fi

# ── 4. libssh ─────────────────────────────────────────────────────────────────
echo ""
echo "[4/7] Building libssh ${LIBSSH_VERSION}..."
if [ ! -f ${INSTALL_PREFIX}/lib/libssh.so ] && \
   [ ! -f /usr/lib/x86_64-linux-gnu/libssh.so ]; then
    rm -rf /tmp/libssh-build
    wget -q "https://www.libssh.org/files/0.10/libssh-${LIBSSH_VERSION}.tar.xz" \
        -O /tmp/libssh.tar.xz
    mkdir -p /tmp/libssh-build
    tar -xf /tmp/libssh.tar.xz -C /tmp/libssh-build --strip-components=1
    cmake -S /tmp/libssh-build -B /tmp/libssh-build/build \
        -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} \
        -DWITH_SERVER=ON
    cmake --build /tmp/libssh-build/build --parallel $(nproc)
    sudo cmake --install /tmp/libssh-build/build
    sudo ldconfig
    echo "  ✓ libssh installed"
else
    echo "  ✓ libssh already installed (skipping)"
fi

# ── 5. Generate cryptographic keys ────────────────────────────────────────────
echo ""
echo "[5/7] Generating cryptographic keys..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "${SCRIPT_DIR}/keys"
KEY_DIR="${SCRIPT_DIR}/keys"

# TLS certificate (P-256 for broad compatibility)
if [ ! -f "${KEY_DIR}/tls_cert.pem" ]; then
    ${OSSL_PREFIX}/bin/openssl req -x509 -newkey ec \
        -pkeyopt ec_paramgen_curve:P-256 \
        -keyout "${KEY_DIR}/tls_key.pem" \
        -out "${KEY_DIR}/tls_cert.pem" \
        -days 365 -nodes \
        -subj "/CN=pqc-trinity-gateway/O=SRM University/C=IN" 2>/dev/null
    echo "  ✓ TLS certificate generated (P-256)"
else
    echo "  ✓ TLS certificate exists (skipping)"
fi

# SSH host key (Ed25519 for wire compatibility)
if [ ! -f "${KEY_DIR}/ssh_host_ed25519" ]; then
    ssh-keygen -t ed25519 -f "${KEY_DIR}/ssh_host_ed25519" -N "" -q
    echo "  ✓ SSH Ed25519 host key generated"
else
    echo "  ✓ SSH host key exists (skipping)"
fi

# ML-DSA-65 host key (via liboqs — custom keygen)
if [ ! -f "${KEY_DIR}/ssh_host_mldsa65" ]; then
    # Generate using a small C helper compiled inline
    cat > /tmp/gen_mldsa65.c << 'KEYGEN_EOF'
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char *argv[]) {
    if (argc < 2) { fprintf(stderr, "Usage: %s <output_base>\n", argv[0]); return 1; }
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig) { fprintf(stderr, "ML-DSA-65 not available\n"); return 1; }
    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) { return 1; }
    char path[512];
    snprintf(path, sizeof(path), "%s", argv[1]);
    FILE *fp = fopen(path, "wb");
    fwrite(sk, 1, sig->length_secret_key, fp);
    fclose(fp);
    snprintf(path, sizeof(path), "%s.pub", argv[1]);
    fp = fopen(path, "wb");
    fwrite(pk, 1, sig->length_public_key, fp);
    fclose(fp);
    fprintf(stderr, "ML-DSA-65 keypair: sk=%zu bytes, pk=%zu bytes\n",
            sig->length_secret_key, sig->length_public_key);
    free(pk); free(sk); OQS_SIG_free(sig);
    return 0;
}
KEYGEN_EOF
    gcc -o /tmp/gen_mldsa65 /tmp/gen_mldsa65.c \
        -I${INSTALL_PREFIX}/include -L${INSTALL_PREFIX}/lib -loqs 2>/dev/null && \
    LD_LIBRARY_PATH=${INSTALL_PREFIX}/lib /tmp/gen_mldsa65 "${KEY_DIR}/ssh_host_mldsa65" && \
    echo "  ✓ ML-DSA-65 host key generated (FIPS 204)" || \
    echo "  ⚠ ML-DSA-65 key generation failed (liboqs may not be installed)"
else
    echo "  ✓ ML-DSA-65 host key exists (skipping)"
fi

# ── 6. Compile PQC Trinity Gateway ───────────────────────────────────────────
echo ""
echo "[6/7] Compiling PQC Trinity Gateway..."
cd "${SCRIPT_DIR}"
mkdir -p build
cd build
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DOPENSSL_ROOT_DIR=${OSSL_PREFIX} \
    -DCMAKE_PREFIX_PATH="${INSTALL_PREFIX};${OSSL_PREFIX}"
cmake --build . --parallel $(nproc)
echo "  ✓ Build complete: $(pwd)/pqc-gateway"

# ── 7. Install config and keys ───────────────────────────────────────────────
echo ""
echo "[7/7] Installing configuration..."
sudo mkdir -p /etc/pqc-gateway/keys /var/log/pqc-gateway
sudo cp "${SCRIPT_DIR}/config/gateway.conf" /etc/pqc-gateway/ 2>/dev/null || true
sudo cp "${SCRIPT_DIR}/config/openssl-pqc.cnf" /etc/pqc-gateway/ 2>/dev/null || true
sudo cp "${KEY_DIR}/"* /etc/pqc-gateway/keys/ 2>/dev/null || true
sudo chmod 600 /etc/pqc-gateway/keys/*_key* 2>/dev/null || true
sudo chmod 600 /etc/pqc-gateway/keys/ssh_host_mldsa65 2>/dev/null || true

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║   ✅ Build Complete                                  ║"
echo "╠═══════════════════════════════════════════════════════╣"
echo "║   Run:   sudo ./build/pqc-gateway                   ║"
echo "║   TLS:   https://localhost:8443                      ║"
echo "║   SSH:   ssh -p 2222 user@localhost                  ║"
echo "║   Audit: /var/log/pqc-gateway/audit.log             ║"
echo "╚═══════════════════════════════════════════════════════╝"
