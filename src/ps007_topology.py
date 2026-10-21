#!/usr/bin/env python3
"""
PS-007 Topology: IPv6 IoT Security Monitoring Simulation
Topology:
  - 1 Router (r1): radvd broadcasting fd00:abcd::/64
  - 1 Monitor (m1): Passive Scapy sniffer + UDP cryptographic session tracker
  - 5 IoT Clients (h1-h5): Fast RFC 8981 IPv6 address rotation (60s preferred lifetime)
  - 1 Open vSwitch (s1): OpenFlow flood rule (priority=100,actions=flood) for passive sniffing
"""

import os
import sys
import time
import argparse
import subprocess
from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def setup_network(test_mode=False, run_xterms=False, duration=90):
    setLogLevel('info')

    info("*** Initializing Mininet for PS-007\n")
    net = Mininet(controller=None, switch=OVSKernelSwitch)

    info("*** Creating Switch (s1)\n")
    s1 = net.addSwitch('s1')

    info("*** Creating Nodes: Router (r1), Monitor (m1), and 5 IoT Clients (h1-h5)\n")
    r1 = net.addHost('r1', sysctls={'net.ipv6.conf.all.disable_ipv6': 0})
    m1 = net.addHost('m1', sysctls={'net.ipv6.conf.all.disable_ipv6': 0})
    
    clients = []
    for i in range(1, 6):
        clients.append(net.addHost(f'h{i}', sysctls={'net.ipv6.conf.all.disable_ipv6': 0}))

    info("*** Linking Nodes to Switch s1\n")
    net.addLink(r1, s1)
    net.addLink(m1, s1)
    for h in clients:
        net.addLink(h, s1)

    info("*** Starting Network\n")
    net.start()

    # Save host namespace PIDs to /tmp/mininet_pids for external launcher scripts
    os.makedirs('/tmp/mininet_pids', exist_ok=True)
    for host in [r1, m1] + clients:
        with open(f'/tmp/mininet_pids/{host.name}.pid', 'w') as f:
            f.write(str(host.pid))

    info("*** Injecting OpenFlow Rule: Flooding all switch traffic for passive monitoring\n")
    # Priority 100 overrides default MAC learning, forcing s1 to flood all packets to m1
    s1.cmd('ovs-ofctl add-flow s1 priority=100,actions=flood')

    info("*** Configuring Router (r1) & Starting radvd daemon\n")
    r1.cmd('sysctl -w net.ipv6.conf.all.forwarding=1')
    r1.cmd('ip -6 addr add fd00:abcd::1/64 dev r1-eth0')

    radvd_conf = """
interface r1-eth0 {
    AdvSendAdvert on;
    MinRtrAdvInterval 3;
    MaxRtrAdvInterval 10;
    prefix fd00:abcd::/64 {
        AdvOnLink on;
        AdvAutonomous on;
        AdvRouterAddr on;
    };
};
"""
    with open('/tmp/radvd.conf', 'w') as f:
        f.write(radvd_conf)
    
    # Remove stale radvd pid file from previous runs
    r1.cmd('kill -9 $(cat /tmp/radvd.pid 2>/dev/null) 2>/dev/null; rm -f /tmp/radvd.pid')
    r1.cmd('radvd -C /tmp/radvd.conf -p /tmp/radvd.pid -m logfile -l /tmp/radvd.log')

    info("*** Configuring Monitor (m1)\n")
    m1.cmd('ip -6 addr add fd00:abcd::2/64 dev m1-eth0')

    info("*** Configuring Clients (h1-h5) for RFC 8981 Fast Address Rotation (60s)\n")
    for i, h in enumerate(clients, start=1):
        eth_intf = f'h{i}-eth0'
        # Accept Router Advertisements
        h.cmd('sysctl -w net.ipv6.conf.all.accept_ra=2')
        h.cmd(f'sysctl -w net.ipv6.conf.{eth_intf}.accept_ra=2')
        
        # Enable RFC 8981 privacy extensions (temporary randomized addresses)
        h.cmd('sysctl -w net.ipv6.conf.all.use_tempaddr=2')
        h.cmd(f'sysctl -w net.ipv6.conf.{eth_intf}.use_tempaddr=2')
        
        # Zero out desync jitter so rotation occurs consistently at 60s
        h.cmd('sysctl -w net.ipv6.conf.all.max_desync_factor=0')
        h.cmd(f'sysctl -w net.ipv6.conf.{eth_intf}.max_desync_factor=0')
        
        # Valid lifetime: 120s, Preferred lifetime: 60s
        h.cmd('sysctl -w net.ipv6.conf.all.temp_valid_lft=120')
        h.cmd(f'sysctl -w net.ipv6.conf.{eth_intf}.temp_valid_lft=120')
        h.cmd('sysctl -w net.ipv6.conf.all.temp_prefered_lft=60')
        h.cmd(f'sysctl -w net.ipv6.conf.{eth_intf}.temp_prefered_lft=60')

    info("*** Waiting 5s for Router Advertisements and initial SLAAC addresses...\n")
    time.sleep(5)
    
    info("\n======================================================\n")
    info("  NETWORK READY\n")
    info("  - Router (r1)  : fd00:abcd::1 (radvd active)\n")
    info("  - Monitor (m1) : fd00:abcd::2 (UDP: 9000)\n")
    info("  - Clients      : h1, h2, h3, h4, h5 (RFC 8981 60s rotation)\n")
    info("======================================================\n\n")

    if test_mode:
        run_automated_test(net, clients, m1, duration)
    elif run_xterms:
        info("*** Launching XTerm windows for m1 and clients...\n")
        net.terms += [m1.pexec('xterm -title "Monitor (m1)" -e "python3 monitor.py" &')]
        for i, h in enumerate(clients, start=1):
            net.terms += [h.pexec(f'xterm -title "Client h{i}" -e "python3 client.py" &')]
        CLI(net)
    else:
        info("*** Manual Mode: Launching Mininet CLI\n")
        info("*** Instructions:\n")
        info("    Start Monitor on m1 : m1 python3 monitor.py &\n")
        info("    Start Clients       : h1 python3 client.py & (repeat for h2-h5)\n")
        info("    Or open xterm       : xterm m1 h1\n\n")
        CLI(net)

    info("*** Stopping Network and Cleaning Up\n")
    r1.cmd('kill -9 $(cat /tmp/radvd.pid 2>/dev/null) 2>/dev/null; rm -f /tmp/radvd.pid')
    os.system('rm -rf /tmp/mininet_pids')
    net.stop()
    os.system('mn -c > /dev/null 2>&1')

def run_automated_test(net, clients, m1, duration=90):
    cwd = os.getcwd()
    info("*** [TEST] Starting Autonomous End-to-End Test...\n")
    
    # Clean old logs
    os.system('rm -f /tmp/monitor.log /tmp/client_h*.log')

    # Start monitor on m1
    info("*** [TEST] Launching monitor.py on m1 (FD00:ABCD::2)...\n")
    monitor_proc = m1.popen(f'env NO_CLEAR=1 python3 {cwd}/monitor.py', stdout=open('/tmp/monitor.log', 'w'), stderr=subprocess.STDOUT)
    time.sleep(2)

    # Start client agents on h1-h5
    client_procs = []
    for i, h in enumerate(clients, start=1):
        info(f"*** [TEST] Launching client.py on h{i}...\n")
        proc = h.popen(f'python3 {cwd}/client.py', stdout=open(f'/tmp/client_h{i}.log', 'w'), stderr=subprocess.STDOUT)
        client_procs.append(proc)
        time.sleep(0.5)

    info("\n*** [TEST] All 5 clients launched! Initializing authentication...\n")
    time.sleep(5)

    print("\n--- INITIAL REGISTRATION LOGS ---")
    for i in range(1, 6):
        log_file = f'/tmp/client_h{i}.log'
        if os.path.exists(log_file):
            with open(log_file) as f:
                content = f.read().strip()
                last_line = content.splitlines()[-1] if content.splitlines() else "starting..."
                print(f"  [h{i}] {last_line}")

    info(f"\n*** [TEST] Entering rotation observation window ({duration}s)...\n")
    info("*** [TEST] Kernel preferred lifetime is 60s. Watching for RFC 8981 address rotation...\n\n")

    start_time = time.time()
    last_print = 0
    while time.time() - start_time < duration:
        elapsed = int(time.time() - start_time)
        remaining = duration - elapsed
        
        if elapsed - last_print >= 10:
            last_print = elapsed
            print(f"[*] Elapsed: {elapsed:2d}s / {duration}s (Address rotation window: ~60s)...")
            # Check for any rotation detected in client logs
            rotations = 0
            for i in range(1, 6):
                log_file = f'/tmp/client_h{i}.log'
                if os.path.exists(log_file):
                    with open(log_file) as f:
                        txt = f.read()
                        if "ROTATION DETECTED" in txt:
                            rotations += 1
            if rotations > 0:
                print(f"    --> [!] {rotations}/5 clients have triggered address rotation and sent HMAC updates!")
        time.sleep(1)

    print("\n" + "=" * 70)
    print("           END-TO-END TEST RESULTS & VERIFICATION")
    print("=" * 70)

    print("\n--- MONITOR OUTPUT SUMMARY (Last 30 lines) ---")
    if os.path.exists('/tmp/monitor.log'):
        with open('/tmp/monitor.log') as f:
            lines = f.readlines()
            for line in lines[-30:]:
                sys.stdout.write(line)

    print("\n--- CLIENT ROTATION EVENT STATUS ---")
    for i in range(1, 6):
        log_file = f'/tmp/client_h{i}.log'
        if os.path.exists(log_file):
            with open(log_file) as f:
                txt = f.read()
                rotated = "ROTATION DETECTED" in txt
                ack_got = "verified with Monitor" in txt
                print(f"  IoT Client h{i}: Rotated={rotated} | HMAC Verified={ack_got}")

    # Terminate background processes
    for p in client_procs:
        p.terminate()
    monitor_proc.terminate()
    print("\n*** [TEST] Automated End-to-End Test Completed.\n")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PS-007 IPv6 IoT Simulation Topology')
    parser.add_argument('--test', action='store_true', help='Run automated end-to-end test')
    parser.add_argument('--xterm', action='store_true', help='Open separate xterm windows for monitor and clients')
    parser.add_argument('--duration', type=int, default=80, help='Duration of test in seconds (default: 80s)')
    args = parser.parse_args()

    os.system('mn -c > /dev/null 2>&1')
    setup_network(test_mode=args.test, run_xterms=args.xterm, duration=args.duration)
