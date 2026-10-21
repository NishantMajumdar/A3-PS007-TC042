#!/usr/bin/env python3
import socket
import subprocess
import time
import sys

MONITOR_IP = "fd00:abcd::2"
PORT = 9000

def get_global_ipv6():
    """Returns the currently active, preferred temporary IPv6 address."""
    # Method 1: Kernel source address selection (RFC 6724) towards monitor
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect((MONITOR_IP, PORT))
        src_ip = s.getsockname()[0]
        s.close()
        if src_ip and src_ip.startswith("fd00:abcd") and not src_ip.startswith("fe80:"):
            return src_ip
    except Exception:
        pass

    # Method 2: iproute2 query specifically for active temporary global address
    try:
        output = subprocess.check_output(
            "ip -6 addr show scope global temporary -deprecated -tentative",
            shell=True, stderr=subprocess.DEVNULL
        ).decode()
        for line in output.splitlines():
            line = line.strip()
            if "inet6 fd00:abcd" in line:
                return line.split()[1].split("/")[0]
    except Exception:
        pass

    # Method 3: Fallback inspection excluding deprecated and tentative
    try:
        output = subprocess.check_output("ip -6 addr", shell=True).decode()
        for line in output.splitlines():
            line = line.strip()
            if "fd00:abcd" in line and "inet6" in line:
                if "deprecated" not in line and "tentative" not in line:
                    for part in line.split():
                        if part.startswith("fd00:abcd") and "/" in part:
                            return part.split("/")[0]
    except Exception:
        pass
    return None

def main():
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.settimeout(5.0)

    print("[*] Starting Anonymous IoT Client Agent (Zero Permanent Info Mode)...")
    
    current_ip = get_global_ipv6()
    while not current_ip:
        print("[*] Waiting for SLAAC IPv6 assignment...")
        time.sleep(2)
        current_ip = get_global_ipv6()
        
    print(f"[+] Initial IPv6 assigned: {current_ip}")
    
    # Blind authentication request - transmitting zero hardware / permanent identifiers
    print(f"[*] Sending blind AUTH_REQUEST to Monitor ({MONITOR_IP}:{PORT})...")
    sock.sendto(b"AUTH_REQUEST", (MONITOR_IP, PORT))
    
    # Receive session token
    ratchet_key = None
    ratchet_ctr = 0
    session_id = None
    raw_token = None

    try:
        data, _ = sock.recvfrom(1024)
        resp = data.decode().strip()
        if resp.startswith("RATCHET|") or resp.startswith("TOKEN|"):
            parts = resp.split("|")
            session_id = parts[1]
            ratchet_key = bytes.fromhex(parts[2])
            print(f"[+] Received Mode B Ratchet Session: {session_id}")
            print(f"[+] Initial Ratchet Key S_0 established.")
        else:
            raw_token = resp
            session_id = resp.split(".")[0]
            print(f"[+] Received Ephemeral Cryptographic Token: {raw_token}")
            print(f"[+] Assigned Pseudonym: {session_id}")
    except socket.timeout:
        print("[-] Monitor did not respond to AUTH_REQUEST. Exiting.")
        sys.exit(1)
        
    # Import ratchet helpers
    from ratchet import ratchet_step, compute_ratchet_tag

    # Watchdog loop: check for RFC 8981 address rotation every 3 seconds
    print(f"\n[*] Starting Watchdog Loop (monitoring RFC 8981 rotation every 3s)...")
    loop_count = 0
    while True:
        time.sleep(3)
        loop_count += 1
        new_ip = get_global_ipv6()
        
        # Check if the kernel has rotated the preferred IPv6 address
        if new_ip and new_ip != current_ip:
            print(f"\n[!] IPv6 ADDRESS ROTATION DETECTED!")
            print(f"    Previous IP : {current_ip}")
            print(f"    New IP      : {new_ip}")
            
            # Send UPDATE message (Mode B Ratchet if key active, else legacy)
            if ratchet_key:
                ratchet_ctr += 1
                tag = compute_ratchet_tag(ratchet_key, new_ip, ratchet_ctr)
                # S_{i+1} = H(S_i)
                ratchet_key = ratchet_step(ratchet_key)
                update_msg = f"UPDATE_RATCHET|{session_id}|{new_ip}|{ratchet_ctr}|{tag}".encode()
                print(f"[*] Sending Mode B UPDATE (ctr={ratchet_ctr}, tag={tag[:12]}...) from new address...")
            else:
                update_msg = f"UPDATE|{raw_token}".encode()
                print("[*] Sending UPDATE packet with cryptographic token from new address...")
            
            # Use fresh socket to guarantee transmission from newly rotated IP
            update_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            update_sock.settimeout(5.0)
            update_sock.sendto(update_msg, (MONITOR_IP, PORT))
            
            try:
                ack, _ = update_sock.recvfrom(1024)
                if ack == b"ACK":
                    print("[✓] Monitor verified HMAC signature and updated pseudonym mapping!")
                    current_ip = new_ip
                elif ack == b"REJECT":
                    print("[✗] AUTH FAILED: Monitor REJECTED update token! (Invalid signature / Session mismatch / Replay)")
                else:
                    print(f"[?] Unexpected response from Monitor: {ack.decode(errors='ignore')}")
            except socket.timeout:
                print("[-] No ACK received from Monitor (Failed to Update / Request timed out).")
            finally:
                update_sock.close()
        else:
            # Send periodic simulated IoT telemetry packet with pseudonym from current active IP
            try:
                t_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                t_sock.sendto(f"DATA|session={session_id}|tick={loop_count}".encode(), (MONITOR_IP, PORT))
                t_sock.close()
            except Exception:
                pass

if __name__ == "__main__":
    main()
