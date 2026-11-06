#!/usr/bin/env bash
#
# K-Valkyrie Host Environment Setup Script
# Installs clang/llvm, libbpf, kernel headers, and sets up python virtualenv.
#

set -euo pipefail

echo "======================================================================"
echo "          K-VALKYRIE KERNEL RUNTIME DEFENSE - HOST SETUP              "
echo "======================================================================"

if [[ $EUID -ne 0 ]]; then
   echo "[-] Please run as root (sudo ./scripts/setup.sh)" 
   exit 1
fi

echo "[*] Detecting Linux distribution..."
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
else
    OS=$(uname -s)
fi
echo "[+] Detected OS: $OS (Kernel: $(uname -r))"

echo "[*] Installing required kernel tools and LLVM/Clang compiler..."
apt-get update -qq
apt-get install -y -qq \
    clang \
    llvm \
    libelf-dev \
    libbpf-dev \
    linux-tools-common \
    linux-tools-$(uname -r) \
    linux-headers-$(uname -r) \
    build-essential \
    pkg-config \
    python3 \
    python3-pip \
    python3-venv \
    curl

echo "[*] Verifying BTF (BPF Type Format) kernel support..."
if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "[+] Kernel BTF enabled: /sys/kernel/btf/vmlinux present."
else
    echo "[!] Warning: /sys/kernel/btf/vmlinux not found. CO-RE requires Kernel 5.15+ with CONFIG_DEBUG_INFO_BTF=y."
fi

echo "[*] Setting up Python virtual environment..."
cd "$(dirname "$0")/.."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
. .venv/bin/activate

echo "[*] Installing daemon Python dependencies..."
pip install --upgrade pip
pip install -r daemon/requirements.txt
pip install pytest

echo "[*] Compiling eBPF probes..."
make

echo "======================================================================"
echo "[+] K-Valkyrie setup complete! You can now start the engine:"
echo "    1. Start the telemetry & GNN daemon:  python daemon/main.py --simulate"
echo "    2. Run interactive simulation:        python scripts/run_demo.py"
echo "    3. Run red-team verification sample:  python exploit_lab/fileless_memfd_loader.py"
echo "======================================================================"
