#!/usr/bin/env python3
import os
import time
from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def setup_network():
    setLogLevel('info')

    info("netstart\n")
    net = Mininet(controller=None, switch=OVSKernelSwitch)

    info("common switc")
    s1 = net.addSwitch('s1')

    info("Router, Monitor, and 5 Clients\n")
    r1 = net.addHost('r1', sysctls={'net.ipv6.conf.all.disable_ipv6': 0})
    m1 = net.addHost('m1', sysctls={'net.ipv6.conf.all.disable_ipv6': 0})
    
    clients = []
    for i in range(1, 6):
        clients.append(net.addHost(f'h{i}', sysctls={'net.ipv6.conf.all.disable_ipv6': 0}))

    info("same network\n")
    net.addLink(r1, s1)
    net.addLink(m1, s1)
    for h in clients:
        net.addLink(h, s1)

    info("*** Starting Network\n")
    net.start()

    info("share packets to all\n")
    # Priority 100 overrides the switch's default MAC learning, forcing it to mirror ALL traffic
    s1.cmd('ovs-ofctl add-flow s1 priority=100,actions=flood')

    info("*** Configuring Router (r1)\n")
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
    r1.cmd('radvd -C /tmp/radvd.conf -p /tmp/radvd.pid -m logfile -l /tmp/radvd.log')

    info("m1 init\n")
    m1.cmd('ip -6 addr add fd00:abcd::2/64 dev m1-eth0')

    info("*** Configuring 5 IoT Clients for Fast RFC 8981 Rotation\n")
    for i, h in enumerate(clients, start=1):
        eth_intf = f'h{i}-eth0'
        # accept ra
        h.cmd('sysctl -w net.ipv6.conf.all.accept_ra=2')
        h.cmd(f'sysctl -w net.ipv6.conf.{eth_intf}.accept_ra=2')
        
        # use rfc8981
        h.cmd('sysctl -w net.ipv6.conf.all.use_tempaddr=2')
        h.cmd(f'sysctl -w net.ipv6.conf.{eth_intf}.use_tempaddr=2')
        
        
        h.cmd('sysctl -w net.ipv6.conf.all.temp_valid_lft=120')
        h.cmd(f'sysctl -w net.ipv6.conf.{eth_intf}.temp_valid_lft=120')
        h.cmd('sysctl -w net.ipv6.conf.all.temp_prefered_lft=60')
        h.cmd(f'sysctl -w net.ipv6.conf.{eth_intf}.temp_prefered_lft=60')

    time.sleep(5)
    
    info("ok\n")
    info("*** - The Monitor is at: fd00:abcd::2\n")
    info("*** - Clients h1-h5 will rotate addresses every 60 seconds.\n")
    CLI(net)

    info("*** Stopping Network and Cleaning Up\n")
    r1.cmd('kill $(cat /tmp/radvd.pid)')
    net.stop()

if __name__ == '__main__':
    os.system('mn -c > /dev/null 2>&1')
    setup_network()
