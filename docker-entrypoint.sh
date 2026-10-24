#!/usr/bin/env bash
set -e

echo "=================================================================="
echo "  PS-007: Privacy-Aware IPv6 IoT Security Monitor"
echo "  Containerized SDN + Zero-MAC NIDS + Utilitarian SOC Dashboard"
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
        cd /app/src
        exec python3 ps007_topology.py "$@"
    fi
    exec "$@"
fi

echo "[+] Open vSwitch is active."
echo "[+] Starting Mininet Topology & Security Monitor..."
echo "------------------------------------------------------------------"
echo "👉 Evaluator Web Dashboard: http://localhost:5000"
echo "------------------------------------------------------------------"

cd /app/src
exec python3 ps007_topology.py
