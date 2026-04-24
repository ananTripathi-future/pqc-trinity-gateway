#!/bin/bash
# ============================================================================
# setup.sh — System Package Installer for PQC Trinity Gateway
#
# Installs all system-level dependencies on Ubuntu 22.04 / Debian 12.
# Run as root: sudo bash setup.sh
#
# Authors: Ojas Sharma & Anant Tripathi — SRM University
# ============================================================================
set -euo pipefail

echo "╔═══════════════════════════════════════════════════════╗"
echo "║   PQC Trinity Gateway — System Setup                 ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Run as root (sudo bash setup.sh)"
    exit 1
fi

echo "[1/3] Installing system packages..."
apt-get update -qq
apt-get install -y \
    build-essential cmake ninja-build gcc g++ make \
    pkg-config python3 python3-pip \
    libssl-dev \
    wget git curl \
    strongswan strongswan-pki libstrongswan-extra-plugins \
    net-tools tcpdump \
    libssh-dev \
    astyle cppcheck

echo ""
echo "[2/3] Creating gateway user and directories..."
id -u pqcgateway &>/dev/null || useradd -r -s /usr/sbin/nologin pqcgateway
mkdir -p /etc/pqc-gateway/keys
mkdir -p /var/log/pqc-gateway
chown pqcgateway:pqcgateway /var/log/pqc-gateway
chmod 750 /var/log/pqc-gateway
chmod 700 /etc/pqc-gateway/keys

echo ""
echo "[3/3] Setting memory lock limits..."
# Allow pqcgateway to lock unlimited memory (required for mlockall)
cat > /etc/security/limits.d/pqc-gateway.conf << 'EOF'
pqcgateway    hard    memlock    unlimited
pqcgateway    soft    memlock    unlimited
root          hard    memlock    unlimited
root          soft    memlock    unlimited
EOF

echo ""
echo "✅ System setup complete."
echo "   Next: run ./build.sh to build dependencies and compile."
