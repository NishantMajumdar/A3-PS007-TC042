#!/usr/bin/env python3
"""
optional_mode_b/optional_mode_b_server.py - Optional Mode B UDP Server Extension

Encapsulates the optional Mode B UDP authentication and ratchet verification service.
When Mode B is enabled, this server listens on UDP port 9000 for:
  - AUTH_REQUEST: Assigns S_0 seed key and enrolls Mode B agent.
  - UPDATE_RATCHET: Verifies forward-secure hash ratchets and monotonic counters.
  - DATA: Processes active agent telemetry heartbeats.
  - UPDATE: Verifies legacy HMAC tokens.

When Mode B is disabled (default), this server is completely inactive, leaving
Mode A to handle black-box IoT devices via passive DAD NS sniffing.
"""

import os
import sys
import time
import socket
import uuid
import hmac
import hashlib
import datetime
from threading import Thread, Lock
from typing import Dict, Any, Optional

from optional_mode_b.ratchet import verify_ratchet_update

MONITOR_SECRET = b"monitorsecretkey67"

def verify_token(token: str):
    """Statelessly verifies legacy HMAC signature against secret master key."""
    try:
        parts = token.split('.', 1)
        if len(parts) != 2:
            return False, None
        session_id, signature = parts
        expected_sig = hmac.new(MONITOR_SECRET, session_id.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected_sig, signature):
            return True, session_id
        return False, None
    except Exception:
        return False, None

class OptionalModeBServer:
    def __init__(
        self,
        pseudonym_mgr,
        session_records: Dict[str, Any],
        unauthenticated_devices: Dict[str, Any],
        ip_to_session: Dict[str, str],
        latest_events: list,
        telemetry,
        db_lock: Lock,
        port: int = 9000
    ):
        self.pseudonym_mgr = pseudonym_mgr
        self.session_records = session_records
        self.unauthenticated_devices = unauthenticated_devices
        self.ip_to_session = ip_to_session
        self.latest_events = latest_events
        self.telemetry = telemetry
        self.db_lock = db_lock
        self.port = port

        self.mode_b_sessions: Dict[str, Dict[str, Any]] = {}  # session_id -> {"key": bytes, "last_ctr": int}
        self._running = False
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[Thread] = None

    def start(self):
        """Starts the optional Mode B UDP listener thread."""
        self._running = True
        self._sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(('::', self.port))
        self._thread = Thread(target=self._listener_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stops the UDP listener."""
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    def _listener_loop(self):
        while self._running:
            try:
                data, addr = self._sock.recvfrom(1024)
                client_ip = addr[0]
                msg = data.decode('utf-8', errors='ignore').strip()
                ts = datetime.datetime.now().strftime("%H:%M:%S")
                now_epoch = time.time()

                if msg.startswith("AUTH_REQUEST"):
                    self._handle_auth_request(client_ip, addr, ts, now_epoch)

                elif msg.startswith("UPDATE_RATCHET|"):
                    self._handle_ratchet_update(msg, client_ip, addr, ts, now_epoch)

                elif msg.startswith("UPDATE|"):
                    self._handle_legacy_update(msg, client_ip, addr, ts, now_epoch)

                elif msg.startswith("DATA|"):
                    self._handle_data_packet(msg, client_ip, addr, ts, now_epoch)

                else:
                    self._sock.sendto(b"REJECT", addr)

            except Exception:
                if not self._running:
                    break

    def _handle_auth_request(self, client_ip: str, addr, ts: str, now_epoch: float):
        session_id = f"IOT-{uuid.uuid4().hex[:4].upper()}"
        s0 = os.urandom(32)
        self.mode_b_sessions[session_id] = {"key": s0, "last_ctr": 0}

        # Register in pseudonym manager
        session_rec, p = self.pseudonym_mgr.get_or_create_session(
            "default", session_id, f"udp-{session_id}", current_time=now_epoch
        )
        self.pseudonym_mgr.bind_address("default", session_id, client_ip, current_time=now_epoch)

        with self.db_lock:
            self.session_records[session_id] = {
                "role": "IoT Device (Mode B)",
                "status": "AUTHENTICATED",
                "session_id": session_id,
                "pseudonym": p,
                "active_ip": client_ip,
                "ip_history": [client_ip],
                "pkts": 1,
                "rotations": 0,
                "first_seen": ts,
                "first_seen_ts": now_epoch,
                "last_seen": ts,
                "last_seen_ts": now_epoch
            }
            self.ip_to_session[client_ip] = session_id
            if client_ip in self.unauthenticated_devices:
                del self.unauthenticated_devices[client_ip]

            event = (ts, "[MODE B]", "\033[1;36m", f"{session_id} ({p}) Mode B enrolled: {client_ip}")
            self.latest_events.insert(0, event)
            if len(self.latest_events) > 5:
                self.latest_events.pop()

        self.telemetry.emit("bind", {"session_id": session_id, "pseudonym": p, "addr": client_ip, "mode": "B"})
        resp_payload = f"RATCHET|{session_id}|{s0.hex()}".encode()
        self._sock.sendto(resp_payload, addr)

    def _handle_ratchet_update(self, msg: str, client_ip: str, addr, ts: str, now_epoch: float):
        parts = msg.split('|')
        if len(parts) < 5:
            self._sock.sendto(b"REJECT", addr)
            return

        session_id = parts[1]
        new_addr = parts[2]
        ctr = int(parts[3])
        tag = parts[4]

        with self.db_lock:
            if session_id in self.mode_b_sessions and session_id in self.session_records:
                sess_data = self.mode_b_sessions[session_id]
                valid, reason, next_k, next_ctr = verify_ratchet_update(
                    sess_data["key"],
                    sess_data["last_ctr"],
                    new_addr,
                    ctr,
                    tag
                )
                if valid:
                    sess_data["key"] = next_k
                    sess_data["last_ctr"] = next_ctr
                    rec = self.session_records[session_id]
                    rec["status"] = "AUTHENTICATED"
                    if client_ip not in rec["ip_history"]:
                        rec["ip_history"].append(client_ip)
                        rec["active_ip"] = client_ip
                        rec["rotations"] += 1
                        self.ip_to_session[client_ip] = session_id
                        if client_ip in self.unauthenticated_devices:
                            del self.unauthenticated_devices[client_ip]
                        event = (ts, "[ROTATED]", "\033[1;32m", f"{session_id} Mode B ratcheted (ctr={next_ctr}) -> {client_ip}")
                    else:
                        event = (ts, "[HEARTBT]", "\033[1;36m", f"{session_id} Mode B heartbeat from {client_ip}")

                    rec["last_seen"] = ts
                    rec["last_seen_ts"] = now_epoch
                    rec["pkts"] += 1
                    self.pseudonym_mgr.bind_address("default", session_id, client_ip, current_time=now_epoch)
                    self.telemetry.emit("rotation", {"session_id": session_id, "addr": client_ip, "ctr": next_ctr, "mode": "B"})
                    self._sock.sendto(b"ACK", addr)
                else:
                    event = (ts, "[REJECT ]", "\033[1;31m", f"Mode B {reason} from {client_ip}")
                    self._sock.sendto(b"REJECT", addr)
                    self.telemetry.emit("alert", {"alert_type": "MODE_B_REJECT", "src": client_ip, "reason": reason})
            else:
                event = (ts, "[REJECT ]", "\033[1;31m", f"Unknown Mode B session {session_id}")
                self._sock.sendto(b"REJECT", addr)

            self.latest_events.insert(0, event)
            if len(self.latest_events) > 5:
                self.latest_events.pop()

    def _handle_legacy_update(self, msg: str, client_ip: str, addr, ts: str, now_epoch: float):
        parts = msg.split('|')
        token = parts[1] if len(parts) > 1 else ""
        is_valid, session_id = verify_token(token)

        with self.db_lock:
            if is_valid and session_id in self.session_records:
                rec = self.session_records[session_id]
                rec["status"] = "AUTHENTICATED"
                if client_ip not in rec["ip_history"]:
                    rec["ip_history"].append(client_ip)
                    rec["active_ip"] = client_ip
                    rec["rotations"] += 1
                    self.ip_to_session[client_ip] = session_id
                    if client_ip in self.unauthenticated_devices:
                        del self.unauthenticated_devices[client_ip]
                    event = (ts, "[ROTATED]", "\033[1;32m", f"{session_id} rotated -> {client_ip}")
                else:
                    event = (ts, "[HEARTBT]", "\033[1;36m", f"{session_id} heartbeat from {client_ip}")

                rec["last_seen"] = ts
                rec["last_seen_ts"] = now_epoch
                rec["pkts"] += 1
                self.telemetry.emit("rotation", {"session_id": session_id, "addr": client_ip, "mode": "B"})
                self._sock.sendto(b"ACK", addr)
            else:
                self._sock.sendto(b"REJECT", addr)

            self.latest_events.insert(0, event)
            if len(self.latest_events) > 5:
                self.latest_events.pop()

    def _handle_data_packet(self, msg: str, client_ip: str, addr, ts: str, now_epoch: float):
        parts = msg.split('|')
        claimed_sid = None
        for part in parts[1:]:
            if part.startswith("session="):
                claimed_sid = part.split('=', 1)[1]

        with self.db_lock:
            if claimed_sid and claimed_sid in self.session_records:
                rec = self.session_records[claimed_sid]
                if self.ip_to_session.get(client_ip) == claimed_sid:
                    rec["pkts"] += 1
                    rec["last_seen"] = ts
                    rec["last_seen_ts"] = now_epoch
                    if "TIMEOUT" in rec["status"] or "STALE" in rec["status"]:
                        rec["status"] = "AUTHENTICATED"
                else:
                    rec["status"] = "FAILED TO UPDATE"
                    event = (ts, "[FAILED ]", "\033[1;31m", f"{claimed_sid} Mode B sent data from {client_ip} WITHOUT UPDATE")
                    self.latest_events.insert(0, event)
                    if len(self.latest_events) > 5:
                        self.latest_events.pop()
