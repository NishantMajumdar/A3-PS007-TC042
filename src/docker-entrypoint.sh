#!/usr/bin/env bash
set -e

# Auto-detect valid X11 socket if DISPLAY is unset or invalid
if [ -n "$DISPLAY" ] && [ -S "/tmp/.X11-unix/X${DISPLAY#*:}" ]; then
    export DISPLAY="$DISPLAY"
else
    for sock in /tmp/.X11-unix/X*; do
        if [ -S "$sock" ]; then
            export DISPLAY=":${sock##*/X}"
            break
        fi
    done
fi
export DISPLAY="${DISPLAY:-:0}"

echo "=================================================================="
echo "  PS-007: Privacy-Aware IPv6 IoT Security Monitor"
echo "  Containerized SDN + Zero-MAC NIDS + Utdocker push nishantmajumdar/ps007-ipv6-monitor:latestilitarian SOC Dashboard"
echo "=================================================================="

# 1. Start Open vSwitch service inside container
echo "[*] Initializing Open vSwitch daemon..."
service openvswitch-switch start || /usr/share/openvswitch/scripts/ovs-ctl start || true

# 2. Clean up any stale Mininet sockets / state
echo "[*] Cleaning network namespaces..."
mn -c > /dev/null 2>&1 || true
rm -rf /tmp/mininet_pids /tmp/radvd.pid /tmp/radvd.log /tmp/ps007_state.json*

# Allow custom commands (e.g. interactive bash, unit tests, or flags to topology)
if [ "$#" -gt 0 ] && [ "$1" != "default" ]; then
    if [[ "$1" == -* ]]; then
        [ -d "/app/src" ] && cd /app/src || cd /app
        exec python3 ps007_topology.py "$@"
    fi
    exec "$@"
fi

echo "[+] Open vSwitch is active."
echo "[+] Starting Mininet Topology..."

[ -d "/app/src" ] && cd /app/src || cd /app
exec python3 ps007_topology.py
