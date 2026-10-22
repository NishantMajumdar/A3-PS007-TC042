#!/usr/bin/env bash
# ==============================================================================
# PS-007 Node Launcher
# Launch a specific Mininet node with automatic execution of its role script:
#   - Client nodes (h1, h2, h3, h4, h5) -> automatically run client.py
#   - Monitor node (m1, monitor)        -> automatically run monitor.py
#   - Router node (r1, router)          -> shows status or opens shell
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MONITOR_SCRIPT="$SCRIPT_DIR/monitor.py"
TOPOLOGY_SCRIPT="$SCRIPT_DIR/ps007_topology.py"

usage() {
    cat << EOF
Usage: $0 [options] <node_name> [custom_command]

Arguments:
  <node_name>       Target Mininet node:
                      - Clients : h1, h2, h3, h4, h5 (opens shell on true black-box client)
                      - Monitor : m1, monitor        (auto-runs monitor.py)
                      - Router  : r1, router         (shows router status)
                      - All     : all                (launches m1 and h1-h5 in xterms)


Options:
  -b, --mode-b      Enable optional Mode B (Active Ratchet Agent / UDP:9000 server)
  -x, --xterm       Launch the node in a separate XTerm graphical window
  -s, --shell       Open an interactive bash shell on the node instead of the default script
  -h, --help        Show this help message

Examples:
  $0 h1             # Run black-box client on h1 (Mode A - Primary)
  $0 --mode-b h1    # Run active ratchet agent on h1 (Mode B - Optional)
  $0 m1             # Run monitor in primary Mode A (Passive Black-Box)
  $0 --mode-b m1    # Run monitor with Mode B UDP server enabled
  $0 -x all         # Launch m1 and all 5 clients in separate XTerm windows
  $0 h1 --shell     # Open an interactive root shell inside h1's network namespace
EOF
    exit 1
}

# Check for help flag early so sudo is not required to view help
for arg in "$@"; do
    if [ "$arg" = "-h" ] || [ "$arg" = "--help" ]; then
        usage
    fi
done

# Auto-elevate to root if not already root
if [ "$EUID" -ne 0 ]; then
    echo "[*] Sudo required to attach to Mininet network namespaces. Elevating..."
    exec sudo "$0" "$@"
fi

# Preserve user X11 authority if running with sudo
if [ -n "$SUDO_USER" ]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    export XAUTHORITY="${XAUTHORITY:-$USER_HOME/.Xauthority}"
    export DISPLAY="${DISPLAY:-:0}"
fi

USE_XTERM=false
USE_SHELL=false
USE_MODE_B=false
NODE=""
CUSTOM_CMD=""

# Parse options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -b|--mode-b)
            USE_MODE_B=true
            shift
            ;;
        -x|--xterm)
            USE_XTERM=true
            shift
            ;;
        -s|--shell)
            USE_SHELL=true
            shift
            ;;
        -h|--help)
            usage
            ;;

        *)
            if [ -z "$NODE" ]; then
                NODE="$1"
            else
                CUSTOM_CMD="$CUSTOM_CMD $1"
            fi
            shift
            ;;
    esac
done

if [ -z "$NODE" ]; then
    echo "[-] Error: Node name is required."
    echo ""
    usage
fi

# Normalize node names
case "$NODE" in
    monitor)
        NODE="m1"
        ;;
    router)
        NODE="r1"
        ;;
esac

# Function to get the PID of a Mininet node
get_node_pid() {
    local target="$1"
    local pid=""

    # 1. Try PID cache file created by ps007_topology.py
    if [ -f "/tmp/mininet_pids/${target}.pid" ]; then
        pid=$(cat "/tmp/mininet_pids/${target}.pid" 2>/dev/null || true)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            echo "$pid"
            return 0
        fi
    fi

    # 2. Fallback: Search processes matching Mininet shell name
    pid=$(pgrep -f "mininet:${target}\b" | head -n 1 || true)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        echo "$pid"
        return 0
    fi

    return 1
}

# Function to check if Mininet is currently active
check_mininet_running() {
    if ! pgrep -f "mininet:" > /dev/null 2>&1 && [ ! -d "/tmp/mininet_pids" ]; then
        echo "[-] Error: Mininet network is not running."
        echo "[*] Start the topology first in another terminal with:"
        echo "    sudo python3 ps007_topology.py"
        echo "    or: sudo ./run_demo.sh"
        exit 1
    fi
}

# Launch a single node
launch_single_node() {
    local target="$1"
    local pid

    if ! pid=$(get_node_pid "$target"); then
        echo "[-] Error: Could not find running node '$target'."
        echo "[*] Available nodes in topology: r1, m1, h1, h2, h3, h4, h5"
        return 1
    fi

    # Determine command to execute
    local cmd_to_run=""
    local title="Mininet Node: $target"

    if [ "$USE_SHELL" = true ]; then
        cmd_to_run="env PS1='mininet:${target}# ' bash"
        title="Node Shell ($target)"
    elif [ -n "$CUSTOM_CMD" ]; then
        cmd_to_run="$CUSTOM_CMD"
        title="Node $target: $CUSTOM_CMD"
    else
        case "$target" in
            m1)
                if [ "$USE_MODE_B" = true ]; then
                    cmd_to_run="python3 -u '$MONITOR_SCRIPT' --enable-mode-b"
                    title="Monitor (m1) [Mode B Enabled]"
                else
                    cmd_to_run="python3 -u '$MONITOR_SCRIPT'"
                    title="Monitor (m1) [Mode A Black-Box]"
                fi
                ;;
            h1|h2|h3|h4|h5)
                if [ "$USE_MODE_B" = true ]; then
                    cmd_to_run="python3 -u '$SCRIPT_DIR/optional_mode_b/optional_client_agent.py'"
                    title="IoT Client ($target) [Mode B Agent]"
                else
                    cmd_to_run="echo -e '\033[1;36m=== IoT Client ($target) [Mode A Black Box] ===\033[0m' && echo 'Node runs zero custom software (True Black Box).' && echo 'Interface: ${target}-eth0' && ip -6 addr show dev ${target}-eth0 | grep inet6 || true && echo '' && echo 'Manual shell ready. Run network commands (e.g. ping -6 fd00:abcd::1):' && env PS1='mininet:${target}# ' bash"
                    title="IoT Client Shell ($target) [Black-Box]"
                fi
                ;;


            r1)
                cmd_to_run="echo '=== Router (r1) Status ===' && ip -6 addr show dev r1-eth0 && echo '' && echo '=== radvd Process ===' && ps aux | grep radvd | grep -v grep && echo '' && bash"
                title="Router (r1)"
                ;;
            *)
                echo "[-] Unrecognized node '$target'. Defaulting to bash shell."
                cmd_to_run="bash"
                ;;
        esac
    fi

    # Execute in XTerm or Foreground
    if [ "$USE_XTERM" = true ]; then
        if ! command -v xterm > /dev/null 2>&1; then
            echo "[-] Error: xterm is not installed. Running in foreground instead."
            exec mnexec -a "$pid" env PYTHONUNBUFFERED=1 TERM="$TERM" bash -c "$cmd_to_run"
        fi

        echo "[+] Launching $target in XTerm window..."
        xterm -title "$title" \
              -geometry 100x32 \
              -bg "#10141a" \
              -fg "#e6edf3" \
              -sb \
              -hold \
              -e "mnexec -a $pid env PYTHONUNBUFFERED=1 TERM=ansi bash -c '$cmd_to_run'" &
    else
        echo "[+] Attaching to $target (PID: $pid)..."
        echo "[+] Executing: $cmd_to_run"
        echo "--------------------------------------------------------"
        cd "$SCRIPT_DIR"
        exec mnexec -a "$pid" env PYTHONUNBUFFERED=1 TERM="$TERM" bash -c "$cmd_to_run"
    fi
}

# Handle 'all' target
if [ "$NODE" = "all" ]; then
    check_mininet_running
    USE_XTERM=true
    echo "[*] Launching Monitor (m1) and all IoT Clients (h1-h5) in separate windows..."
    launch_single_node "m1"
    sleep 1
    for client in h1 h2 h3 h4 h5; do
        launch_single_node "$client"
        sleep 0.5
    done
    echo "[+] All nodes launched successfully."
    exit 0
fi

# Main execution
check_mininet_running
launch_single_node "$NODE"
