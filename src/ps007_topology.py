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
    s1 = net.addSwitch('s1', protocols='OpenFlow10,OpenFlow13')

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

    info("*** Configuring Switch Flows: NORMAL forwarding + Per-Port Mirror with VLAN (4100+in_port)\n")
    s1.cmd('ovs-vsctl set bridge s1 protocols=OpenFlow10,OpenFlow13')
    s1.cmd('ovs-ofctl -O OpenFlow13 del-flows s1')

    # Determine m1 openflow port on s1
    m1_link = net.linksBetween(m1, s1)[0]
    m1_port = s1.ports[m1_link.intf2]

    # Default fallback flow: NORMAL L2/L3 forwarding
    s1.cmd('ovs-ofctl -O OpenFlow13 add-flow s1 "table=0,priority=1,actions=NORMAL"')

    # Ingress from m1: NORMAL forwarding only (prevent mirroring m1 traffic back to m1)
    s1.cmd(f'ovs-ofctl -O OpenFlow13 add-flow s1 "table=0,priority=100,in_port={m1_port},actions=NORMAL"')
    # Prevent switch from flooding broadcast/multicast NORMAL traffic to m1 (m1 receives mirrored copies only)
    s1.cmd(f'ovs-ofctl mod-port s1 {m1_port} no-flood')

    # Ingress from r1 and clients: NORMAL forwarding + mirrored copy with pushed VLAN (4100+in_port) to m1
    for node in [r1] + clients:
        link = net.linksBetween(node, s1)[0]
        in_p = s1.ports[link.intf2]
        vlan_id = 4100 + in_p
        s1.cmd(f'ovs-ofctl -O OpenFlow13 add-flow s1 "table=0,priority=100,in_port={in_p},actions=NORMAL,push_vlan:0x8100,set_field:{vlan_id}->vlan_vid,output:{m1_port}"')

    info("*** Configuring Router (r1) & Starting radvd daemon\n")
    r1.cmd('sysctl -w net.ipv6.conf.all.forwarding=1')
    r1.cmd('ip -6 addr add fd00:abcd::1/64 dev r1-eth0')
    r1.cmd('ip -6 addr add fe80::1/64 dev r1-eth0 2>/dev/null || true')

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
    m1.cmd('ethtool -K m1-eth0 rxvlan off 2>/dev/null || true')
    m1.cmd('ethtool -K m1-eth0 rx-vlan-offload off 2>/dev/null || true')

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
        info("*** Launching XTerm windows for m1 and client shells...\n")
        net.terms += [m1.pexec('xterm -title "Monitor (m1)" -e "python3 monitor.py" &')]
        for i, h in enumerate(clients, start=1):
            net.terms += [h.pexec(f'xterm -title "Black-Box Client h{i}" -e "env PS1=\'mininet:h{i}# \' bash" &')]
        CLI(net)
    else:
        info("*** Manual Mode: Launching Mininet CLI\n")
        info("*** Instructions:\n")
        info("    Start Monitor on m1 : m1 python3 monitor.py &\n")
        info("    Black-Box Clients   : h1..h5 run ZERO software. Test manually: h1 ping -6 fd00:abcd::1\n")
        info("    Or open launcher    : ./launch_node.sh h1\n\n")
        CLI(net)

    info("*** Stopping Network and Cleaning Up\n")
    r1.cmd('kill -9 $(cat /tmp/radvd.pid 2>/dev/null) 2>/dev/null; rm -f /tmp/radvd.pid')
    os.system('rm -rf /tmp/mininet_pids')
    net.stop()
    os.system('mn -c > /dev/null 2>&1')

def run_automated_test(net, clients, m1, duration=90):
    cwd = os.getcwd()
    info("*** [TEST] Starting Autonomous End-to-End Test (Mode A: Zero-Software Black-Box Clients)...\n")
    
    # Clean old logs
    os.system('rm -f /tmp/monitor.log /tmp/client_h*.log')

    # Start monitor on m1
    info("*** [TEST] Launching monitor.py on m1 (FD00:ABCD::2)...\n")
    monitor_proc = m1.popen(f'env NO_CLEAR=1 python3 {cwd}/monitor.py', stdout=open('/tmp/monitor.log', 'w'), stderr=subprocess.STDOUT)
    time.sleep(2)

    # Client nodes run absolutely nothing automatically
    info("*** [TEST] Client nodes (h1-h5) running ZERO processes (True Black Box).\n")
    info("*** [TEST] Waiting for kernel SLAAC and DAD Neighbor Solicitations...\n")
    time.sleep(5)

    info(f"\n*** [TEST] Entering observation window ({duration}s)...\n")
    info("*** [TEST] You can run commands manually via './launch_node.sh h1' in another terminal.\n\n")

    start_time = time.time()
    last_print = 0
    while time.time() - start_time < duration:
        elapsed = int(time.time() - start_time)
        remaining = duration - elapsed
        
        if elapsed - last_print >= 10:
            last_print = elapsed
            print(f"[*] Elapsed: {elapsed:2d}s / {duration}s...")
            # Check for kernel address rotation
            rotations = 0
            for i, h in enumerate(clients, start=1):
                addr_count = h.cmd("ip -6 addr show dev h" + str(i) + "-eth0 | grep 'scope global temporary' | wc -l").strip()
                try:
                    if int(addr_count) >= 2:
                        rotations += 1
                except Exception:
                    pass
            if rotations > 0:
                print(f"    --> [!] {rotations}/5 black-box clients have kernel RFC 8981 rotations active!")
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

    print("\n--- CLIENT KERNEL ADDRESS STATUS ---")
    for i, h in enumerate(clients, start=1):
        addrs = h.cmd(f"ip -6 -o addr show dev h{i}-eth0 scope global | awk '{{print $4}}'").strip().splitlines()
        print(f"  IoT Client h{i} (Black Box): Current Kernel Addresses = {addrs}")

    monitor_proc.terminate()
    print("\n*** [TEST] Test Completed.\n")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PS-007 IPv6 IoT Simulation Topology')
    parser.add_argument('--test', action='store_true', help='Run automated end-to-end test')
    parser.add_argument('--xterm', action='store_true', help='Open separate xterm windows for monitor and clients')
    parser.add_argument('--duration', type=int, default=80, help='Duration of test in seconds (default: 80s)')
    args = parser.parse_args()

    os.system('mn -c > /dev/null 2>&1')
    setup_network(test_mode=args.test, run_xterms=args.xterm, duration=args.duration)
