#!/usr/bin/env bash
# PS-007 End-to-End Test & Demo Runner

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "=========================================================="
echo "  PS-007: IPv6 IoT Security Monitor (HMAC-SHA256)"
echo "=========================================================="

if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run with sudo: sudo ./run_demo.sh [mode]"
    echo ""
    echo "Usage modes:"
    echo "  sudo ./run_demo.sh --test     (Automated 80s end-to-end test with rotation verification)"
    echo "  sudo ./run_demo.sh --xterm    (Interactive test spawning XTerm windows for m1 and h1-h5)"
    echo "  sudo ./run_demo.sh            (Interactive Mininet CLI mode)"
    exit 1
fi

# Ensure clean Mininet environment
echo "[*] Cleaning up Mininet artifacts..."
mn -c > /dev/null 2>&1 || true
rm -f /tmp/radvd.pid /tmp/radvd.conf /tmp/radvd.log /tmp/monitor.log /tmp/client_h*.log

# Check if X11 forwarding is available for xterm
if [ "$1" == "--xterm" ]; then
    if [ -n "$SUDO_USER" ]; then
        xhost +local: > /dev/null 2>&1 || true
    fi
fi

# Execute topology script
echo "[*] Launching ps007_topology.py with arguments: $@"
python3 ps007_topology.py "$@"
