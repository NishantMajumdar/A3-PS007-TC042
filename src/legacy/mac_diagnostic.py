#!/usr/bin/env python3
"""
LEGACY / DIAGNOSTIC ONLY - DO NOT IMPORT OR USE IN MAIN SYSTEM.

This script was the initial diagnostic stepping-stone to verify Mininet
packet delivery across Open vSwitch before implementing PS-007 compliance.
It relies directly on hardware MAC addresses (Ether.src), which is strictly
forbidden in the final production system.
"""

import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, IPv6, Ether

mac_to_ips = {}

def process_packet(packet):
    if Ether in packet and IPv6 in packet:
        mac = packet[Ether].src
        ipv6 = packet[IPv6].src
        if mac not in mac_to_ips:
            mac_to_ips[mac] = set()
        if ipv6 not in mac_to_ips[mac]:
            mac_to_ips[mac].add(ipv6)
            print(f"[LEGACY MAC DIAGNOSTIC] Host MAC {mac} -> New IPv6: {ipv6} (Total tracked: {len(mac_to_ips[mac])})")

if __name__ == "__main__":
    print("[!] Running Legacy MAC Diagnostic Tracker on m1-eth0...")
    print("[!] VIOLATION WARNING: This inspects hardware MAC addresses for network debugging only.")
    try:
        sniff(iface="m1-eth0", filter="ip6", prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n[+] Diagnostic finished. Final MAC mapping table:")
        for mac, ips in mac_to_ips.items():
            print(f"  {mac}: {list(ips)}")
        sys.exit(0)
