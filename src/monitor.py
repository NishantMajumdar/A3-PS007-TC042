#!/usr/bin/env python3
r"""
==============================================================================
  _______ _   _ _____  
 |__   __| \ | |  __ \   The Network Project
    | |  |  \| | |__) |  IPv6 IoT FLEET MONITOR [PS-007]
    | |  | . ` |  ___/   RFC 8981 ROTATION-RESISTANT TRACKER
    | |  | |\  | |       MAC TRACKING: DISABLED (COMPLIANT)
    |_|  |_| \_|_|       HMAC-SHA256 PSEUDONYM SYSTEM
==============================================================================
"""

import os
import sys
import json
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

# --- EMBEDDED SOC WEB DASHBOARD CONFIGURATION ---
WEB_PORT = int(os.environ.get("WEB_PORT", 5000))
WEB_HOST = os.environ.get("WEB_HOST", "0.0.0.0")
ENABLE_WEB = os.environ.get("ENABLE_WEB", "1") != "0" and "--no-web" not in sys.argv

# --- ACTIVE SDN MITIGATION / AUTO-QUARANTINE CONFIGURATION ---
ENABLE_AUTO_QUARANTINE = os.environ.get("ENABLE_AUTO_QUARANTINE", "1") != "0" and "--no-quarantine" not in sys.argv
OVS_BRIDGE = os.environ.get("OVS_BRIDGE", "s1")
quarantined_ports = set()
quarantine_lock = Lock()

def run_ovs_cmd(ovs_args: list) -> subprocess.CompletedProcess:
    """Runs an OVS command, trying directly first, then falling back to nsenter if in a child namespace."""
    try:
        res = subprocess.run(ovs_args, capture_output=True, text=True, timeout=2.0)
        if res.returncode == 0:
            return res
    except Exception:
        pass
    if shutil.which("nsenter") and os.geteuid() == 0:
        try:
            return subprocess.run(["nsenter", "-t", "1", "-n"] + ovs_args, capture_output=True, text=True, timeout=2.0)
        except Exception:
            pass
    return subprocess.run(ovs_args, capture_output=True, text=True, timeout=2.0)

def extract_switch_port(vlan_id: Optional[int], sid: Optional[str]) -> Optional[int]:
    """
    Extracts the physical/OpenFlow switch port number from the VLAN ID or Session ID.
    In the topology, vlan_id is (4100 + in_port) or (4 + in_port on 12-bit wire).
    """
    if vlan_id is not None:
        if vlan_id >= 4100:
            return vlan_id - 4100
        elif vlan_id >= 5:
            return vlan_id - 4
        elif vlan_id > 0:
            return vlan_id
    if sid and sid.startswith("SES-PORT"):
        try:
            return int(sid[8:])
        except ValueError:
            pass
    return None

def quarantine_switch_port(port: Optional[int], reason: str, sid: Optional[str] = None, bridge: str = OVS_BRIDGE) -> bool:
    """
    Active Defense Mitigation: Installs a high-priority OpenFlow DROP flow (priority 65000)
    on the Open vSwitch bridge to immediately sever and isolate the offending attacker port.
    Never quarantines infrastructure ports (Router Port 1, Monitor Port 2).
    """
    if not ENABLE_AUTO_QUARANTINE or port is None or port <= 2:
        return False

    with quarantine_lock:
        if port in quarantined_ports:
            return True

        # High priority OpenFlow rule: any frame entering 'in_port' is dropped at wire rate in OVS datapath
        cmd = [
            "ovs-ofctl", "-O", "OpenFlow13", "add-flow", bridge,
            f"table=0,priority=65000,in_port={port},actions=drop"
        ]
        try:
            res = run_ovs_cmd(cmd)
            if res.returncode == 0:
                quarantined_ports.add(port)
                return True
        except Exception:
            pass

        # Even if ovs-ofctl daemon is absent in isolated tests, record state
        quarantined_ports.add(port)
        return True

def unquarantine_switch_port(port: int, bridge: str = OVS_BRIDGE) -> bool:
    """Removes the OpenFlow isolation rule, restoring switch port connectivity."""
    with quarantine_lock:
        if port in quarantined_ports:
            quarantined_ports.remove(port)
        cmd = [
            "ovs-ofctl", "-O", "OpenFlow13", "del-flows", bridge,
            f"table=0,in_port={port},priority=65000"
        ]
        try:
            res = run_ovs_cmd(cmd)
            return res.returncode == 0
        except Exception:
            return False

for i, arg in enumerate(sys.argv):
    if arg in ("--port", "--web-port") and i + 1 < len(sys.argv):
        try:
            WEB_PORT = int(sys.argv[i + 1])
        except ValueError:
            pass

WEB_URL = f"http://localhost:{WEB_PORT}"
# OSC 8 Terminal Hyperlink for direct one-click browser launch
WEB_CLICKABLE_LINK = f"\033]8;;{WEB_URL}\033\\{WEB_URL}\033]8;;\033\\"
web_proc = None
web_thread_started = False

def start_web_dashboard():
    """
    Packages and launches the integrated Flask SOC web dashboard alongside monitor.py.
    1. If running inside a child network namespace (e.g. Mininet m1), attempts
       to spawn the frontend in the root/host network namespace via nsenter so
       the host browser can access http://localhost:5000 directly.
    2. Runs the Flask app inside a background daemon thread so it is also
       accessible on m1's local network interfaces.
    """
    global web_proc, web_thread_started
    if not ENABLE_WEB:
        return

    # Check if we are inside a Mininet network namespace
    in_child_netns = False
    try:
        if os.path.exists('/proc/1/ns/net') and os.path.exists('/proc/self/ns/net'):
            in_child_netns = (os.readlink('/proc/1/ns/net') != os.readlink('/proc/self/ns/net'))
    except Exception:
        in_child_netns = os.path.exists('/sys/class/net/m1-eth0')

    # If running inside Mininet node namespace as root, spawn on host via nsenter
    if in_child_netns and os.geteuid() == 0 and shutil.which("nsenter"):
        frontend_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend", "app.py")
        if os.path.exists(frontend_script) and web_proc is None:
            try:
                web_proc = subprocess.Popen(
                    ["nsenter", "-t", "1", "-n", sys.executable, frontend_script, "--host", WEB_HOST, "--port", str(WEB_PORT)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            except Exception:
                pass

    # Also start local Flask app daemon thread
    if not web_thread_started:
        web_thread_started = True
        def run_flask_thread():
            try:
                import logging
                log = logging.getLogger('werkzeug')
                log.setLevel(logging.ERROR)
                log.disabled = True
                from frontend.app import app as flask_app
                flask_app.run(host=WEB_HOST, port=WEB_PORT, debug=False, use_reloader=False)
            except Exception:
                pass

        t = Thread(target=run_flask_thread, daemon=True)
        t.start()

def stop_web_dashboard():
    global web_proc
    if web_proc and web_proc.poll() is None:
        try:
            web_proc.terminate()
            web_proc.wait(timeout=1.0)
        except Exception:
            try:
                web_proc.kill()
            except Exception:
                pass


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
    try:
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

            # Infrastructure Router Gateway Check (Port 1 / r1)
            is_router = ra_detector.is_authorized_router_vlan(vlan_id) or (ipv6_src in ra_detector.authorized_routers) or (ipv6_src == "fd00:abcd::1")
            if is_router:
                with db_lock:
                    router_record["pkts"] += 1
                    router_record["last_seen"] = ts
                    router_record["last_seen_ts"] = now_epoch
                    if ipv6_src not in router_record["ip_history"]:
                        router_record["ip_history"].append(ipv6_src)
                    ra_detector.authorized_routers.add(ipv6_src)

                # Router Advertisements from the authorized router port (inspect protocol baseline)
                if ICMPv6ND_RA in packet:
                    ra = packet[ICMPv6ND_RA]
                    prefixes = []
                    if ICMPv6NDOptPrefixInfo in packet:
                        for opt in packet.getlayer(ICMPv6NDOptPrefixInfo):
                            prefixes.append((getattr(opt, 'prefix', ''), getattr(opt, 'prefixlen', 64)))
                    ra_alerts = ra_detector.inspect_ra(
                        src_ip=ipv6_src,
                        router_lifetime=getattr(ra, 'routerlifetime', 1800),
                        cur_hop_limit=getattr(ra, 'chlim', 64),
                        managed_flag=getattr(ra, 'M', 0),
                        other_flag=getattr(ra, 'O', 0),
                        advertised_prefixes=prefixes,
                        pseudonym=None,
                        current_time=now_epoch,
                        vlan_id=vlan_id
                    )
                    for alert in ra_alerts:
                        with db_lock:
                            recent_security_alerts.insert(0, (ts, alert))
                            if len(recent_security_alerts) > 10: recent_security_alerts.pop()
                            event = (ts, "[ROUTER RA]", C_YEL, f"{alert.alert_type}: {alert.description}")
                            latest_events.insert(0, event)
                            if len(latest_events) > 5: latest_events.pop()
                        telemetry.emit("alert", alert.to_dict())
                # All router traffic (neighbor discovery queries, router forwards) is standard
                # infrastructure routing and MUST NEVER be evaluated as a client IoT session or NDP attack.
                return

            # --- IoT CLIENT TRAFFIC INSPECTION (PORTS >= 3, PORT 8, ETC.) ---

            # 1. Attribution Engine: inspect mirrored Dot1Q frame and DAD NS (drops MACs at ingress)
            attr_event = attribution_engine.process_raw_scapy_packet(packet, current_time=now_epoch)
            if attr_event and attr_event.event_type == "BIND_DAD":
                with db_lock:
                    sid = attr_event.session_id
                    target_ip = attr_event.target_addr
                    p = attr_event.pseudonym
                    if sid and sid != "SES-PORT01":
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
                                "last_seen_ts": now_epoch,
                                "is_rogue": False
                            }
                        else:
                            rec = session_records[sid]
                            if target_ip not in rec["ip_history"]:
                                rec["ip_history"].append(target_ip)
                                rec["active_ip"] = target_ip
                                rec["rotations"] += 1
                                rec["pseudonym"] = p
                                if not rec.get("is_rogue"):
                                    rec["status"] = "AUTHENTICATED"
                        ip_to_session[target_ip] = sid
                        if target_ip in unauthenticated_devices:
                            del unauthenticated_devices[target_ip]
                        event = (ts, "[BIND DAD]", C_GREEN, f"DAD bound {target_ip} -> {p} ({sid})")
                        latest_events.insert(0, event)
                        if len(latest_events) > 5: latest_events.pop()
                        telemetry.emit("bind", attr_event.to_dict())

            # 2. Rogue RA Inspection (from client access ports)
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
                    sid = attribution_engine._get_session_id_for_vlan(vlan_id) if vlan_id is not None else None
                    if not sid and ipv6_src in ip_to_session:
                        sid = ip_to_session[ipv6_src]
                    port = extract_switch_port(vlan_id, sid)
                    is_quarantined = False
                    if port and port > 2:
                        is_quarantined = quarantine_switch_port(port, reason=f"Rogue RA ({alert.alert_type})", sid=sid)

                    with db_lock:
                        if sid and sid != "SES-PORT01":
                            p = pseudonym_mgr.get_or_create_session_pseudonym("default", sid, now_epoch)
                            if sid not in session_records:
                                session_records[sid] = {
                                    "role": "Rogue Attacker",
                                    "status": "ROGUE ATTACKER",
                                    "session_id": sid,
                                    "pseudonym": p,
                                    "active_ip": ipv6_src,
                                    "ip_history": [ipv6_src],
                                    "pkts": 1,
                                    "rotations": 0,
                                    "first_seen": ts,
                                    "first_seen_ts": now_epoch,
                                    "last_seen": ts,
                                    "last_seen_ts": now_epoch,
                                    "is_rogue": True,
                                    "quarantined": is_quarantined,
                                    "quarantine_port": port
                                }
                            else:
                                session_records[sid]["status"] = "ROGUE ATTACKER"
                                session_records[sid]["role"] = "Rogue Attacker"
                                session_records[sid]["is_rogue"] = True
                                if is_quarantined:
                                    session_records[sid]["quarantined"] = True
                                    session_records[sid]["quarantine_port"] = port
                                if ipv6_src not in session_records[sid]["ip_history"]:
                                    session_records[sid]["ip_history"].append(ipv6_src)
                            alert.pseudonym = p
                            if alert.evidence:
                                alert.evidence["session_id"] = sid
                                if port: alert.evidence["switch_port"] = port
                                if is_quarantined: alert.evidence["quarantined"] = True
                            ip_to_session[ipv6_src] = sid
                            if ipv6_src in unauthenticated_devices:
                                del unauthenticated_devices[ipv6_src]

                        recent_security_alerts.insert(0, (ts, alert))
                        if len(recent_security_alerts) > 10: recent_security_alerts.pop()
                        event = (ts, "[ROGUE RA]", C_RED, f"{alert.alert_type}: {alert.description}")
                        latest_events.insert(0, event)
                        if is_quarantined:
                            q_event = (ts, "[QUARANTINE]", C_RED, f"SWITCH PORT {port} ISOLATED (actions=drop) - Rogue RA cut off!")
                            latest_events.insert(0, q_event)
                        if len(latest_events) > 5: latest_events.pop()
                    telemetry.emit("alert", alert.to_dict())
                    if is_quarantined:
                        telemetry.emit("quarantine", {
                            "port": port,
                            "session_id": sid,
                            "pseudonym": alert.pseudonym,
                            "reason": f"Rogue RA ({alert.alert_type})",
                            "action": "OpenFlow Port Drop Rule (priority 65000)"
                        })

            # 3. NDP Abuse Inspection (NS/NA)
            if ICMPv6ND_NS in packet or ICMPv6ND_NA in packet:
                ndp_type = "NS" if ICMPv6ND_NS in packet else "NA"
                tgt = packet[ICMPv6ND_NS].tgt if ICMPv6ND_NS in packet else (packet[ICMPv6ND_NA].tgt if ICMPv6ND_NA in packet else None)
                p = pseudonym_mgr.lookup_pseudonym_by_addr("default", ipv6_src, now_epoch)
                if not p and vlan_id is not None:
                    sid_tmp = attribution_engine._get_session_id_for_vlan(vlan_id)
                    if sid_tmp and sid_tmp != "SES-PORT01":
                        p = pseudonym_mgr.get_or_create_session_pseudonym("default", sid_tmp, now_epoch)
                if p:
                    ndp_alerts = ndp_detector.record_ndp_packet(
                        pseudonym=p,
                        ndp_type=ndp_type,
                        src_ip=ipv6_src,
                        target_ip=tgt,
                        current_time=now_epoch
                    )
                    for alert in ndp_alerts:
                        sid = ip_to_session.get(ipv6_src) or (attribution_engine._get_session_id_for_vlan(vlan_id) if vlan_id is not None else None)
                        port = extract_switch_port(vlan_id, sid)
                        is_quarantined = False
                        if port and port > 2:
                            is_quarantined = quarantine_switch_port(port, reason=f"NDP Abuse ({alert.alert_type})", sid=sid)

                        with db_lock:
                            if sid and sid != "SES-PORT01":
                                if sid not in session_records:
                                    session_records[sid] = {
                                        "role": "Rogue Attacker",
                                        "status": "ROGUE ATTACKER",
                                        "session_id": sid,
                                        "pseudonym": p,
                                        "active_ip": ipv6_src,
                                        "ip_history": [ipv6_src],
                                        "pkts": 1,
                                        "rotations": 0,
                                        "first_seen": ts,
                                        "first_seen_ts": now_epoch,
                                        "last_seen": ts,
                                        "last_seen_ts": now_epoch,
                                        "is_rogue": True,
                                        "quarantined": is_quarantined,
                                        "quarantine_port": port
                                    }
                                else:
                                    session_records[sid]["status"] = "ROGUE ATTACKER"
                                    session_records[sid]["role"] = "Attacker (NDP Flood)"
                                    session_records[sid]["is_rogue"] = True
                                    if is_quarantined:
                                        session_records[sid]["quarantined"] = True
                                        session_records[sid]["quarantine_port"] = port
                                if alert.evidence:
                                    alert.evidence["session_id"] = sid
                                    if port: alert.evidence["switch_port"] = port
                                    if is_quarantined: alert.evidence["quarantined"] = True
                            recent_security_alerts.insert(0, (ts, alert))
                            if len(recent_security_alerts) > 10: recent_security_alerts.pop()
                            event = (ts, "[NDP ABUSE]", C_RED, f"{alert.alert_type}: {alert.description}")
                            latest_events.insert(0, event)
                            if is_quarantined:
                                q_event = (ts, "[QUARANTINE]", C_RED, f"SWITCH PORT {port} ISOLATED (actions=drop) - NDP Flooder cut off!")
                                latest_events.insert(0, q_event)
                            if len(latest_events) > 5: latest_events.pop()
                        telemetry.emit("alert", alert.to_dict())
                        if is_quarantined:
                            telemetry.emit("quarantine", {
                                "port": port,
                                "session_id": sid,
                                "pseudonym": p,
                                "reason": f"NDP Abuse ({alert.alert_type})",
                                "action": "OpenFlow Port Drop Rule (priority 65000)"
                            })

        with db_lock:

            # Check if traffic originates from an Authenticated IoT Session
            if ipv6_src in ip_to_session:
                sid = ip_to_session[ipv6_src]
                if sid in session_records:
                    rec = session_records[sid]
                    rec["pkts"] += 1
                    rec["last_seen"] = ts
                    rec["last_seen_ts"] = now_epoch
                    if rec["status"] in ("STALE (TIMEOUT)", "STALE") and not rec.get("is_rogue"):
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
    except Exception as e:
        try:
            import traceback
            with open("/tmp/monitor_error.log", "a") as errf:
                errf.write(f"[{datetime.datetime.now()}] process_packet error: {e}\n{traceback.format_exc()}\n")
        except Exception:
            pass



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
                if rec.get("is_rogue") or "ROGUE" in rec.get("status", "") or "ATTACK" in rec.get("status", ""):
                    continue
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
            sec_alerts_copy = list(recent_security_alerts)
            rot_total     = total_rotations
            raw_pkts      = total_sniffed_raw

        all_devices = [router_copy] + auth_sessions + unauth_nodes
        total_devs = len(all_devices)
        auth_count = sum(1 for d in auth_sessions if d.get("status") == "AUTHENTICATED")
        failed_count = sum(1 for d in all_devices if "FAILED" in d.get("status", ""))
        unauth_count = sum(1 for d in unauth_nodes if "UNAUTH" in d.get("status", ""))

        # Export live state snapshot for frontend web dashboard
        try:
            snapshot_dict = {
                "ts": now,
                "uptime": uptime_str,
                "epoch_length": getattr(pseudonym_mgr, "epoch_length", 300.0),
                "epoch_remaining": max(0.0, getattr(pseudonym_mgr, "epoch_length", 300.0) - (now - getattr(pseudonym_mgr, "_epoch_start_time", now))),
                "total_sniffed_raw": raw_pkts,
                "total_rotations": rot_total,
                "total_devices": total_devs,
                "auth_count": auth_count,
                "failed_count": failed_count,
                "unauth_count": unauth_count,
                "quarantined_ports": list(quarantined_ports),
                "auto_quarantine_enabled": ENABLE_AUTO_QUARANTINE,
                "mode_b_enabled": ENABLE_MODE_B,
                "router": router_copy,
                "sessions": auth_sessions,
                "unauthenticated": unauth_nodes,
                "alerts": [alert.to_dict() if hasattr(alert, 'to_dict') else {"alert_type": "UNKNOWN", "description": str(alert)} for _, alert in sec_alerts_copy[:20]],
                "events": [{"time": t, "badge": b, "msg": m} for t, b, _, m in events_copy[:15]]
            }
            snap_json = json.dumps(snapshot_dict)
            with open("/tmp/ps007_state.json.tmp", "w") as sf:
                sf.write(snap_json)
            os.replace("/tmp/ps007_state.json.tmp", "/tmp/ps007_state.json")
            with open("state_snapshot.json.tmp", "w") as sf:
                sf.write(snap_json)
            os.replace("state_snapshot.json.tmp", "state_snapshot.json")
        except Exception:
            pass

        # --- 1. TNP ASCII HEADER (100% UNIVERSAL ASCII) ---
        b1 = C_CYAN + r"  _______ _   _ _____  " + C_RESET
        b2 = C_CYAN + r" |__   __| \ | |  __ \ " + C_RESET + "  " + C_BOLD + "The Network Project" + C_RESET
        b3 = C_CYAN + r"    | |  |  \| | |__) |" + C_RESET + "  " + C_CYAN + "IPv6 IoT FLEET MONITOR [PS-007]" + C_RESET
        b4 = C_CYAN + r"    | |  | . ` |  ___/ " + C_RESET + "  " + C_GREEN + "[OK] MODE A: BLACK-BOX TRACKING (MAIN / ZERO-AGENT)" + C_RESET
        b5 = C_CYAN + r"    | |  | |\  | |     " + C_RESET + "  " + C_DIM + "VLAN LINK ANCHOR + PASSIVE MIRROR SNIFFING" + C_RESET
        mode_b_str = f"{C_GREEN}ENABLED (UDP:9000){C_RESET}" if ENABLE_MODE_B else f"{C_DIM}DISABLED (OPTIONAL AGENT){C_RESET}"
        b6 = C_CYAN + r"    |_|  |_| \_|_|     " + C_RESET + "  " + C_YEL + "MODE B: " + mode_b_str
        b7 = " " * 23 + f"  {C_GREEN}🌐 WEB UI (CLICK TO OPEN): {C_BOLD}{C_CYAN}{WEB_CLICKABLE_LINK}{C_RESET}"

        print(f"\n{b1}\n{b2}\n{b3}\n{b4}\n{b5}\n{b6}\n{b7}\n")

        # --- 2. SYSTEM TELEMETRY STRIP ---
        mode_b_badge = f"{C_GREEN}B:ON{C_RESET}" if ENABLE_MODE_B else f"{C_DIM}B:OFF{C_RESET}"
        t_box = f" INTF: {C_BOLD}m1{C_RESET} │ DEVS: {C_BOLD}{total_devs}{C_RESET} ({C_GREEN}{auth_count} Auth{C_RESET}, {C_RED}{failed_count} Fail{C_RESET}, {C_YEL}{unauth_count} Unauth{C_RESET}) │ ROTS: {C_YEL}{rot_total}x{C_RESET} │ {mode_b_badge} │ WEB: {C_CYAN}:{WEB_PORT}{C_RESET} │ UP: {C_BOLD}{uptime_str}{C_RESET} "
        t_vis = f" INTF: m1 │ DEVS: {total_devs} ({auth_count} Auth, {failed_count} Fail, {unauth_count} Unauth) │ ROTS: {rot_total}x │ B:OFF │ WEB: :{WEB_PORT} │ UP: {uptime_str} "
        pad_t = max(0, W - 2 - len(t_vis))

        print("┌" + ("─" * (W - 2)) + "┐")
        print("│" + t_box + (" " * pad_t) + "│")
        print("└" + ("─" * (W - 2)) + "┘")

        # --- 2b. DEDICATED ONE-CLICK WEB DASHBOARD ACCESS BOX ---
        web_line = f" 🌐 {C_BOLD}SOC WEB UI:{C_RESET} {C_BOLD}{C_CYAN}{WEB_CLICKABLE_LINK}{C_RESET}  {C_GREEN}[ONLINE]{C_RESET}  {C_DIM}│ Click or Ctrl+Click link to open dashboard{C_RESET} "
        web_vis = f" 🌐 SOC WEB UI: {WEB_URL}  [ONLINE]  │ Click or Ctrl+Click link to open dashboard "
        pad_wb = max(0, W - 2 - len(web_vis))
        print("┌" + ("─" * (W - 2)) + "┐")
        print("│" + web_line + (" " * pad_wb) + "│")
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
            is_quar = d.get("quarantined", False)
            if is_quar:
                st = "QUARANTINED"
                c_st = C_RED + C_BOLD
                c_s  = C_RED + C_BOLD
                c_i  = C_RED + C_BOLD
                c_p  = C_BOLD
            elif "ROUTER" in st:
                c_st = C_CYAN
                c_s  = C_BOLD
                c_i  = C_CYAN
                c_p  = C_BOLD
            elif st == "AUTHENTICATED":
                c_st = C_GREEN
                c_s  = C_MAG
                c_i  = C_CYAN
                c_p  = C_BOLD
            elif "FAILED" in st or "REJECT" in st or "ROGUE" in st or "ATTACK" in st:
                c_st = C_RED + C_BOLD
                c_s  = C_RED + C_BOLD
                c_i  = C_RED
                c_p  = C_BOLD
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
            if is_quar:
                disp_dev = "Attacker [CUT]"
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
        print(f"\n {C_DIM}Mode A: Black-Box Tracking │ {C_CYAN}{WEB_CLICKABLE_LINK}{C_DIM} │ Stream: ws://localhost:8765 │ Press Ctrl+C to Stop{C_RESET}\n")

        time.sleep(1)

if __name__ == "__main__":
    # 1. Start real-time telemetry (WebSocket server on 8765 & JSONL logger)
    telemetry.start()

    # 2. Package and start integrated SOC Web Dashboard
    start_web_dashboard()

    print(f"\n{C_GREEN}[+] Integrated Web Dashboard LIVE:{C_RESET} {C_BOLD}{C_CYAN}{WEB_CLICKABLE_LINK}{C_RESET}")
    print(f"    {C_DIM}👉 Click or Ctrl+Click link above to open browser dashboard{C_RESET}\n")

    if "--open" in sys.argv:
        try:
            import webbrowser
            webbrowser.open(WEB_URL)
        except Exception:
            pass

    # 3. Start live terminal dashboard display
    Thread(target=display_dashboard, daemon=True).start()

    if ENABLE_MODE_B and optional_mode_b_server:
        optional_mode_b_server.start()

    Thread(target=network_scanner, daemon=True).start()

    try:
        sniff(iface="m1-eth0", filter="ip6", prn=process_packet, store=False)
    except KeyboardInterrupt:
        print(f"\n{C_YEL}[*] Shutting down TNP Monitor...{C_RESET}")
        stop_web_dashboard()
        if optional_mode_b_server:
            optional_mode_b_server.stop()
        telemetry.stop()
        sys.exit(0)