#!/usr/bin/env python3
r"""
==============================================================================
  _______ _   _ _____  
 |__   __| \ | |  __ \   TNP CYBERSECURITY RESEARCH LABS
    | |  |  \| | |__) |  IPv6 IoT FLEET MONITOR [PS-007]
    | |  | . ` |  ___/   RFC 8981 ROTATION-RESISTANT TRACKER
    | |  | |\  | |       MAC TRACKING: DISABLED (COMPLIANT)
    |_|  |_| \_|_|       HMAC-SHA256 PSEUDONYM SYSTEM
==============================================================================
"""

import os
import sys
import time
import socket
import hmac
import hashlib
import uuid
import datetime
import shutil
import subprocess
from threading import Thread, Lock
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, IPv6, ICMPv6EchoRequest, ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptPrefixInfo, Dot1Q, send

from pseudonym import PseudonymManager
from attribution import AttributionEngine, AttributionEvent
from detectors import RogueRADetector, NDPAbuseDetector, SecurityAlert
from telemetry import TelemetryEmitter

# --- HIGH-CONTRAST TERMINAL PALETTE (LIGHT & DARK THEME COMPLIANT) ---
C_RESET = "\033[0m"
C_BOLD  = "\033[1m"
C_DIM   = "\033[2m"
C_CYAN  = "\033[1;36m"
C_GREEN = "\033[1;32m"
C_YEL   = "\033[1;33m"
C_MAG   = "\033[1;35m"
C_RED   = "\033[1;31m"

# --- CORE ENGINES INITIALIZATION (MODE A: PRIMARY BLACK-BOX TRACKER) ---
pseudonym_mgr = PseudonymManager(epoch_length_seconds=300.0, default_addr_ttl=120.0)
attribution_engine = AttributionEngine(pseudonym_mgr)
ra_detector = RogueRADetector(authorized_routers=["fd00:abcd::1", "fe80::1"], authorized_vlan=4101)

ndp_detector = NDPAbuseDetector()
telemetry = TelemetryEmitter(log_path="events.jsonl", ws_port=8765)
recent_security_alerts = []

# --- IN-MEMORY DISCOVERY & ATTRIBUTION DATABASE ---
db_lock = Lock()


# 1. Router Record (Infrastructure Gateway)
router_record = {
    "role": "Gateway (r1)",
    "status": "ROUTER / ACTIVE",
    "session_id": "GATEWAY",
    "active_ip": "fd00:abcd::1",
    "ip_history": ["fd00:abcd::1"],
    "pkts": 0,
    "rotations": 0,
    "last_seen": None,
    "last_seen_ts": time.time()
}

# 2. Authenticated IoT Clients: session_id -> record
session_records = {}

# 3. Unauthenticated Subnet Devices: ipv6_address -> record
unauthenticated_devices = {}

# Mapping from IP to Session-ID
ip_to_session = {}

# Stream of recent handshake and rotation events
latest_events = []
total_sniffed_raw = 0
total_rotations = 0
start_time = time.time()

# --- OPTIONAL MODE B CONFIGURATION (ACTIVE AGENT SERVER) ---
ENABLE_MODE_B = os.environ.get("ENABLE_MODE_B", "0") == "1" or "--enable-mode-b" in sys.argv
optional_mode_b_server = None

if ENABLE_MODE_B:
    from optional_mode_b.optional_mode_b_server import OptionalModeBServer
    optional_mode_b_server = OptionalModeBServer(
        pseudonym_mgr=pseudonym_mgr,
        session_records=session_records,
        unauthenticated_devices=unauthenticated_devices,
        ip_to_session=ip_to_session,
        latest_events=latest_events,
        telemetry=telemetry,
        db_lock=db_lock,
        port=9000
    )


# --- ACTIVE NETWORK SCANNER (ZERO MAC INSPECTION) ---
def network_scanner():
    """Periodically probes the network to discover all connected nodes without MAC fingerprinting."""
    time.sleep(2)
    while True:
        try:
            # Probe 1: Router r1 direct ICMPv6 Echo Request
            probe_router = IPv6(dst="fd00:abcd::1")/ICMPv6EchoRequest()
            send(probe_router, iface="m1-eth0", verbose=False)

            # Probe 2: All-Nodes Multicast (ff02::1) to solicit replies from all active devices
            probe_all_nodes = IPv6(dst="ff02::1")/ICMPv6EchoRequest()
            send(probe_all_nodes, iface="m1-eth0", verbose=False)
        except Exception:
            # Fallback ping in case raw socket is unavailable
            try:
                subprocess.Popen("ping -c 1 -6 -I m1-eth0 ff02::1 >/dev/null 2>&1", shell=True)
                subprocess.Popen("ping -c 1 -6 fd00:abcd::1 >/dev/null 2>&1", shell=True)
            except Exception:
                pass

        time.sleep(10)

# --- PASSIVE SNIFFING & DEVICE CLASSIFICATION ---
def process_packet(packet):
    """Passively captures mirrored IPv6 packets and updates device discovery & packet metrics."""
    global total_sniffed_raw
    if IPv6 in packet:
        # All genuine mirrored traffic from s1 carries an ingress Dot1Q VLAN tag.
        # Drop untagged packets (multicast frames flooded by OVS NORMAL action)
        # to prevent duplicate accounting and false port-attribution errors.
        if Dot1Q not in packet:
            return

        total_sniffed_raw += 1
        vlan_id = packet[Dot1Q].vlan
        ipv6_src = packet[IPv6].src
        ipv6_dst = packet[IPv6].dst

        # Ignore loopback and monitor's own interface
        if ipv6_src == "::1" or ipv6_src == "fd00:abcd::2":
            return

        ts = datetime.datetime.now().strftime("%H:%M:%S")
        now_epoch = time.time()

        # 1. Attribution Engine: inspect mirrored Dot1Q frame and DAD NS (drops MACs at ingress)
        attr_event = attribution_engine.process_raw_scapy_packet(packet, current_time=now_epoch)
        if attr_event and attr_event.event_type == "BIND_DAD":
            with db_lock:
                sid = attr_event.session_id
                target_ip = attr_event.target_addr
                p = attr_event.pseudonym
                if sid not in session_records:
                    session_records[sid] = {
                        "role": "IoT Device",
                        "status": "AUTHENTICATED",
                        "session_id": sid,
                        "pseudonym": p,
                        "active_ip": target_ip,
                        "ip_history": [target_ip],
                        "pkts": 1,
                        "rotations": 0,
                        "first_seen": ts,
                        "first_seen_ts": now_epoch,
                        "last_seen": ts,
                        "last_seen_ts": now_epoch
                    }
                else:
                    rec = session_records[sid]
                    if target_ip not in rec["ip_history"]:
                        rec["ip_history"].append(target_ip)
                        rec["active_ip"] = target_ip
                        rec["rotations"] += 1
                        rec["pseudonym"] = p
                        rec["status"] = "AUTHENTICATED"
                ip_to_session[target_ip] = sid
                if target_ip in unauthenticated_devices:
                    del unauthenticated_devices[target_ip]
                event = (ts, "[BIND DAD]", C_GREEN, f"DAD bound {target_ip} -> {p} ({sid})")
                latest_events.insert(0, event)
                if len(latest_events) > 5: latest_events.pop()
                telemetry.emit("bind", attr_event.to_dict())

        # 2. Rogue RA Inspection
        if ICMPv6ND_RA in packet:
            ra = packet[ICMPv6ND_RA]
            prefixes = []
            if ICMPv6NDOptPrefixInfo in packet:
                for opt in packet.getlayer(ICMPv6NDOptPrefixInfo):
                    prefixes.append((getattr(opt, 'prefix', ''), getattr(opt, 'prefixlen', 64)))
            vlan_id = packet[Dot1Q].vlan if Dot1Q in packet else None
            ra_alerts = ra_detector.inspect_ra(
                src_ip=ipv6_src,
                router_lifetime=getattr(ra, 'routerlifetime', 1800),
                cur_hop_limit=getattr(ra, 'chlim', 64),
                managed_flag=getattr(ra, 'M', 0),
                other_flag=getattr(ra, 'O', 0),
                advertised_prefixes=prefixes,
                pseudonym=pseudonym_mgr.lookup_pseudonym_by_addr("default", ipv6_src, now_epoch),
                current_time=now_epoch,
                vlan_id=vlan_id
            )

            for alert in ra_alerts:
                with db_lock:
                    recent_security_alerts.insert(0, (ts, alert))
                    if len(recent_security_alerts) > 5: recent_security_alerts.pop()
                    event = (ts, "[ROGUE RA]", C_RED, f"{alert.alert_type}: {alert.description}")
                    latest_events.insert(0, event)
                    if len(latest_events) > 5: latest_events.pop()
                telemetry.emit("alert", alert.to_dict())

        # 3. NDP Abuse Inspection (NS/NA)
        if ICMPv6ND_NS in packet or ICMPv6ND_NA in packet:
            ndp_type = "NS" if ICMPv6ND_NS in packet else "NA"
            tgt = packet[ICMPv6ND_NS].tgt if ICMPv6ND_NS in packet else (packet[ICMPv6ND_NA].tgt if ICMPv6ND_NA in packet else None)
            p = pseudonym_mgr.lookup_pseudonym_by_addr("default", ipv6_src, now_epoch)
            if p:
                ndp_alerts = ndp_detector.record_ndp_packet(
                    pseudonym=p,
                    ndp_type=ndp_type,
                    src_ip=ipv6_src,
                    target_ip=tgt,
                    current_time=now_epoch
                )
                for alert in ndp_alerts:
                    with db_lock:
                        recent_security_alerts.insert(0, (ts, alert))
                        if len(recent_security_alerts) > 5: recent_security_alerts.pop()
                        event = (ts, "[NDP ABUSE]", C_RED, f"{alert.alert_type}: {alert.description}")
                        latest_events.insert(0, event)
                        if len(latest_events) > 5: latest_events.pop()
                    telemetry.emit("alert", alert.to_dict())

        with db_lock:
            # Check if traffic originates from the Router (r1)
            if ipv6_src == "fd00:abcd::1":
                router_record["pkts"] += 1
                router_record["last_seen"] = ts
                router_record["last_seen_ts"] = now_epoch
                return

            # Check if traffic originates from an Authenticated IoT Session
            if ipv6_src in ip_to_session:
                sid = ip_to_session[ipv6_src]
                if sid in session_records:
                    rec = session_records[sid]
                    rec["pkts"] += 1
                    rec["last_seen"] = ts
                    rec["last_seen_ts"] = now_epoch
                    if rec["status"] in ("STALE (TIMEOUT)", "STALE"):
                        rec["status"] = "AUTHENTICATED"
                return

            # Traffic from an unauthenticated device on the subnet fd00:abcd::/64
            if ipv6_src.startswith("fd00:abcd:"):
                if ipv6_src not in unauthenticated_devices:
                    unauthenticated_devices[ipv6_src] = {
                        "role": "Unauthorized",
                        "status": "UNAUTHENTICATED",
                        "session_id": "---",
                        "active_ip": ipv6_src,
                        "ip_history": [ipv6_src],
                        "pkts": 0,
                        "rotations": 0,
                        "first_seen": ts,
                        "first_seen_ts": now_epoch,
                        "last_seen": ts,
                        "last_seen_ts": now_epoch
                    }
                    event = (ts, "[UNAUTH ]", C_YEL, f"Traffic from unauthenticated IP: {ipv6_src}")
                    latest_events.insert(0, event)
                    if len(latest_events) > 5:
                        latest_events.pop()

                unrec = unauthenticated_devices[ipv6_src]
                unrec["pkts"] += 1
                unrec["last_seen"] = ts
                unrec["last_seen_ts"] = now_epoch



# --- UI CELL PADDING HELPER ---
def cell(text, width, color=""):
    text = str(text)
    if len(text) > width:
        text = text[:width - 1] + "."
    padded = f"{text:<{width}}"
    if color:
        return f"{color}{padded}{C_RESET}"
    return padded

# --- LIVE DASHBOARD RENDERING ---
def display_dashboard():
    no_clear = os.environ.get("NO_CLEAR", "0") == "1"

    while True:
        if not no_clear:
            sys.stdout.write("\033[H\033[J")
            sys.stdout.flush()

        term_cols = shutil.get_terminal_size((80, 24)).columns
        W = max(78, min(100, term_cols - 2))

        uptime_secs = int(time.time() - start_time)
        hrs = uptime_secs // 3600
        mins = (uptime_secs % 3600) // 60
        secs = uptime_secs % 60
        uptime_str = f"{hrs:02d}:{mins:02d}:{secs:02d}"

        now = time.time()
        # Periodically purge expired pseudonym mappings & detector states
        if int(now) % 5 == 0:
            purge_stats = pseudonym_mgr.purge(now)
            if purge_stats.get("sessions_purged", 0) > 0 or purge_stats.get("addr_mappings_purged", 0) > 0:
                telemetry.emit("expiry", purge_stats)
            active_pseudos = set()
            with pseudonym_mgr._lock:
                for st in pseudonym_mgr._tenant_stores.values():
                    active_pseudos.update(st.pseudonym_to_session.keys())
            ndp_detector.purge_expired_pseudonyms(active_pseudos)

        with db_lock:
            # 1. Update session activity state (ACTIVE vs IDLE)
            for sid, rec in session_records.items():
                last_seen_epoch = rec.get("last_seen_ts", now)
                silence = now - last_seen_epoch
                if rec["status"] in ("AUTHENTICATED", "ACTIVE", "IDLE"):
                    if silence > 30:
                        rec["status"] = "IDLE"
                    else:
                        rec["status"] = "AUTHENTICATED"


            # 2. Check unauthenticated devices sending network traffic without authenticating
            for u_ip, u_rec in unauthenticated_devices.items():
                fs = u_rec.get("first_seen_ts", now)
                if u_rec["status"] == "UNAUTHENTICATED" and (now - fs) > 5 and u_rec.get("pkts", 0) >= 2:
                    u_rec["status"] = "AUTH FAILED"
                    u_rec["role"] = "Unauthorized"
                    event = (datetime.datetime.now().strftime("%H:%M:%S"), "[FAILED ]", C_RED, f"{u_ip} failed to auth (unauthorized traffic)")
                    latest_events.insert(0, event)
                    if len(latest_events) > 5:
                        latest_events.pop()

            # Build unified list of all discovered devices: Router + Authenticated Clients + Unauthenticated
            router_copy = dict(router_record)
            auth_sessions = [dict(v) for v in session_records.values()]
            unauth_nodes  = [dict(v) for v in unauthenticated_devices.values()]
            events_copy   = list(latest_events)
            rot_total     = total_rotations
            raw_pkts      = total_sniffed_raw

        all_devices = [router_copy] + auth_sessions + unauth_nodes
        total_devs = len(all_devices)
        auth_count = sum(1 for d in auth_sessions if d.get("status") == "AUTHENTICATED")
        failed_count = sum(1 for d in all_devices if "FAILED" in d.get("status", ""))
        unauth_count = sum(1 for d in unauth_nodes if "UNAUTH" in d.get("status", ""))

        # --- 1. TNP ASCII HEADER (100% UNIVERSAL ASCII) ---
        b1 = C_CYAN + r"  _______ _   _ _____  " + C_RESET
        b2 = C_CYAN + r" |__   __| \ | |  __ \ " + C_RESET + "  " + C_BOLD + "TNP CYBERSECURITY RESEARCH LABS" + C_RESET
        b3 = C_CYAN + r"    | |  |  \| | |__) |" + C_RESET + "  " + C_CYAN + "IPv6 IoT FLEET MONITOR [PS-007]" + C_RESET
        b4 = C_CYAN + r"    | |  | . ` |  ___/ " + C_RESET + "  " + C_GREEN + "[OK] MODE A: BLACK-BOX TRACKING (MAIN / ZERO-AGENT)" + C_RESET
        b5 = C_CYAN + r"    | |  | |\  | |     " + C_RESET + "  " + C_DIM + "VLAN LINK ANCHOR + PASSIVE MIRROR SNIFFING" + C_RESET
        mode_b_str = f"{C_GREEN}ENABLED (UDP:9000){C_RESET}" if ENABLE_MODE_B else f"{C_DIM}DISABLED (OPTIONAL AGENT){C_RESET}"
        b6 = C_CYAN + r"    |_|  |_| \_|_|     " + C_RESET + "  " + C_YEL + "MODE B: " + mode_b_str

        print(f"\n{b1}\n{b2}\n{b3}\n{b4}\n{b5}\n{b6}\n")

        # --- 2. SYSTEM TELEMETRY STRIP ---
        mode_b_badge = f"{C_GREEN}B:ON{C_RESET}" if ENABLE_MODE_B else f"{C_DIM}B:OFF{C_RESET}"
        t_box = f" INTF: {C_BOLD}m1{C_RESET} │ DEVS: {C_BOLD}{total_devs}{C_RESET} ({C_GREEN}{auth_count} Auth{C_RESET}, {C_RED}{failed_count} Fail{C_RESET}, {C_YEL}{unauth_count} Unauth{C_RESET}) │ ROTS: {C_YEL}{rot_total}x{C_RESET} │ {mode_b_badge} │ WS: {C_GREEN}:8765{C_RESET} │ UP: {C_BOLD}{uptime_str}{C_RESET} "
        t_vis = f" INTF: m1 │ DEVS: {total_devs} ({auth_count} Auth, {failed_count} Fail, {unauth_count} Unauth) │ ROTS: {rot_total}x │ B:OFF │ WS: :8765 │ UP: {uptime_str} "
        pad_t = max(0, W - 2 - len(t_vis))

        print("┌" + ("─" * (W - 2)) + "┐")
        print("│" + t_box + (" " * pad_t) + "│")
        print("└" + ("─" * (W - 2)) + "┘")

        # --- 3. DYNAMIC NETWORK SCAN TABLE: ALL DISCOVERED DEVICES ---
        c_dev  = 12
        c_stat = 16
        c_sid  = 9
        c_pk   = 5
        c_ip   = max(20, W - 16 - (c_dev + c_stat + c_sid + c_pk))

        border_top = "┌" + ("─" * (c_dev + 2)) + "┬" + ("─" * (c_stat + 2)) + "┬" + ("─" * (c_sid + 2)) + "┬" + ("─" * (c_ip + 2)) + "┬" + ("─" * (c_pk + 2)) + "┐"
        border_mid = "├" + ("─" * (c_dev + 2)) + "┼" + ("─" * (c_stat + 2)) + "┼" + ("─" * (c_sid + 2)) + "┼" + ("─" * (c_ip + 2)) + "┼" + ("─" * (c_pk + 2)) + "┤"
        border_bot = "└" + ("─" * (c_dev + 2)) + "┴" + ("─" * (c_stat + 2)) + "┴" + ("─" * (c_sid + 2)) + "┴" + ("─" * (c_ip + 2)) + "┴" + ("─" * (c_pk + 2)) + "┘"

        h_dev  = cell("DEVICE/ROLE", c_dev, C_BOLD)
        h_stat = cell("AUTH STATUS", c_stat, C_BOLD)
        h_sid  = cell("PSEUDONYM", c_sid, C_BOLD)
        h_ip   = cell("ACTIVE IPv6 ADDRESS", c_ip, C_BOLD)
        h_pk   = cell("PKTS", c_pk, C_BOLD)

        title_scan = " NETWORK SCAN: DISCOVERED DEVICES & AUTHENTICATION STATUS "
        pad_ts = max(0, W - 2 - len(title_scan) - 2)
        print("\n┌──" + title_scan + ("─" * pad_ts) + "┐")
        print(border_top)
        print(f"│ {h_dev} │ {h_stat} │ {h_sid} │ {h_ip} │ {h_pk} │")
        print(border_mid)

        for d in all_devices:
            st = d["status"]
            if "ROUTER" in st:
                c_st = C_CYAN
                c_s  = C_BOLD
                c_i  = C_CYAN
                c_p  = C_BOLD
            elif st == "AUTHENTICATED":
                c_st = C_GREEN
                c_s  = C_MAG
                c_i  = C_CYAN
                c_p  = C_BOLD
            elif "FAILED" in st or "REJECT" in st:
                c_st = C_RED + C_BOLD
                c_s  = C_RED
                c_i  = C_RED
                c_p  = C_DIM
            elif "TIMEOUT" in st or "STALE" in st:
                c_st = C_YEL + C_BOLD
                c_s  = C_YEL
                c_i  = C_YEL
                c_p  = C_DIM
            else:
                c_st = C_YEL
                c_s  = C_DIM
                c_i  = C_DIM
                c_p  = C_DIM

            disp_dev = d["role"]
            r_dev  = cell(disp_dev, c_dev, C_BOLD)
            r_stat = cell(st, c_stat, c_st)
            disp_sid = d.get("pseudonym", d.get("session_id", "---"))
            r_sid  = cell(disp_sid, c_sid, c_s)

            # Format IP address with rotation tag if applicable
            disp_ip = d["active_ip"]
            if d.get("rotations", 0) > 0:
                disp_ip = f"{d['active_ip']} ({d['rotations']}x)"
            r_ip   = cell(disp_ip, c_ip, c_i)

            pk_num = d["pkts"]
            pk_str = f"{pk_num}p" if pk_num > 999 else f"{pk_num}pk"
            r_pk   = cell(pk_str, c_pk, c_p)

            print(f"│ {r_dev} │ {r_stat} │ {r_sid} │ {r_ip} │ {r_pk} │")

        print(border_bot)

        # --- 4. ACTIVE IPv6 PRIVACY ADDRESS ROTATION CHAINS ---
        title_chains = " ACTIVE IPv6 PRIVACY ADDRESS ROTATION CHAINS "
        pad_tc = max(0, W - 2 - len(title_chains) - 2)
        print("\n┌──" + title_chains + ("─" * pad_tc) + "┐")

        chains_printed = 0
        for s in auth_sessions:
            sid = s.get("pseudonym", s["session_id"])
            st = s.get("status", "AUTHENTICATED")
            act_ip = s["ip_history"][-1]
            st_color = C_GREEN if st == "AUTHENTICATED" else C_DIM
            st_text = "[ACTIVE]" if st == "AUTHENTICATED" else "[IDLE]"

            if len(s["ip_history"]) > 1:
                chains_printed += 1
                rot_count = len(s["ip_history"]) - 1
                vis_len1 = len(f" {sid} ({s['role']})  {st_text} {act_ip} ({rot_count}x rotated)")
                pad1 = max(0, W - 2 - vis_len1)
                print(f"│ {C_MAG}{sid}{C_RESET} {C_DIM}({s['role']}){C_RESET}  {st_color}{st_text}{C_RESET} {C_CYAN}{act_ip}{C_RESET} {C_DIM}({rot_count}x rotated){C_RESET}" + (" " * pad1) + "│")
                for i_old, old_ip in enumerate(reversed(s["ip_history"][:-1]), 1):
                    tag = f"[PREV {i_old}]"
                    vis_len2 = len(f"               {tag} {old_ip}")
                    pad2 = max(0, W - 2 - vis_len2)
                    print(f"│               {C_DIM}{tag} {old_ip}{C_RESET}" + (" " * pad2) + "│")
            elif s.get("pkts", 0) > 0 or s.get("session_id", "").startswith("SES-"):
                chains_printed += 1
                vis_len1 = len(f" {sid} ({s['role']})  {st_text} {act_ip}")
                pad1 = max(0, W - 2 - vis_len1)
                print(f"│ {C_MAG}{sid}{C_RESET} {C_DIM}({s['role']}){C_RESET}  {st_color}{st_text}{C_RESET} {C_CYAN}{act_ip}{C_RESET}" + (" " * pad1) + "│")


        if chains_printed == 0:
            empty_rot = " No address rotations triggered yet (RFC 8981 rotates at ~60s)..."
            pad_er = max(0, W - 2 - len(empty_rot))
            print("│" + C_DIM + empty_rot + C_RESET + (" " * pad_er) + "│")
        print("└" + ("─" * (W - 2)) + "┘")

        # --- 5. REAL-TIME SECURITY ALERTS & ANOMALY DETECTIONS ---
        title_sec = " REAL-TIME SECURITY ALERTS & ANOMALY DETECTIONS "
        pad_sec = max(0, W - 2 - len(title_sec) - 2)
        print("\n┌──" + title_sec + ("─" * pad_sec) + "┐")

        with db_lock:
            sec_alerts_copy = list(recent_security_alerts)

        if not sec_alerts_copy:
            no_alert_msg = " [✓] Zero security anomalies detected. NDP rate limits & RAs nominal."
            pad_na = max(0, W - 2 - len(no_alert_msg))
            print("│" + C_GREEN + no_alert_msg + C_RESET + (" " * pad_na) + "│")
        else:
            for ts, alert in sec_alerts_copy[:4]:
                color = C_RED if alert.severity in ("CRITICAL", "HIGH") else C_YEL
                p_tag = f"({alert.pseudonym})" if alert.pseudonym else "(UNAUTH)"
                alert_text = f"[{alert.severity}] {alert.alert_type} {p_tag}: {alert.description}"
                rem = W - 2 - 12
                trunc = (alert_text[:rem - 3] + "...") if len(alert_text) > rem else alert_text
                vis_len = 8 + len(ts) + 2 + len(trunc)
                pad_line = max(0, W - 2 - vis_len)
                print(f"│ {color}[ALERT]{C_RESET} {ts}  {C_BOLD}{trunc}{C_RESET}" + (" " * pad_line) + "│")

        print("└" + ("─" * (W - 2)) + "┘")

        # --- 6. RECENT HANDSHAKE & ROTATION EVENTS ---
        title_events = " RECENT HANDSHAKE & ROTATION EVENTS "
        pad_events = max(0, W - 2 - len(title_events) - 2)
        print("\n┌──" + title_events + ("─" * pad_events) + "┐")

        if not events_copy:
            empty_msg = " Waiting for client authentication requests (AUTH_REQUEST)..."
            pad_e = max(0, W - 2 - len(empty_msg))
            print("│" + C_DIM + empty_msg + C_RESET + (" " * pad_e) + "│")
        else:
            for ts, badge, color, msg in events_copy:
                rem = W - 2 - 21
                msg_trunc = (msg[:rem - 3] + "...") if len(msg) > rem else msg
                pad_line = max(0, rem - len(msg_trunc))
                print("│ " + f"{color}{badge}{C_RESET} {ts}  {C_BOLD}{msg_trunc}{C_RESET}" + (" " * pad_line) + "│")

        print("└" + ("─" * (W - 2)) + "┘")

        # --- 7. FOOTER STATUS ---
        mode_b_desc = "Mode B (Agent): Active (:9000)" if ENABLE_MODE_B else "Mode B (Agent): Disabled (Optional)"
        print(f"\n {C_DIM}Mode A: Black-Box Tracking (VLAN 4100+Port) │ {mode_b_desc} │ Stream: ws://localhost:8765 │ Press Ctrl+C to Stop{C_RESET}\n")

        time.sleep(1)

if __name__ == "__main__":
    telemetry.start()
    Thread(target=display_dashboard, daemon=True).start()
    if ENABLE_MODE_B and optional_mode_b_server:
        optional_mode_b_server.start()
    Thread(target=network_scanner, daemon=True).start()
    try:
        sniff(iface="m1-eth0", filter="ip6", prn=process_packet, store=False)
    except KeyboardInterrupt:
        print(f"\n{C_YEL}[*] Shutting down TNP Monitor...{C_RESET}")
        if optional_mode_b_server:
            optional_mode_b_server.stop()
        telemetry.stop()
        sys.exit(0)