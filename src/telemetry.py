#!/usr/bin/env python3
"""
telemetry.py - PS-007 Structured Event Logger, WebSocket Broadcaster, and Replay Engine

Features:
  1. Emits structured JSONL events (rotation, bind, alert, expiry).
  2. Pure standard-library RFC 6455 WebSocket server (zero external dependencies).
  3. Replay engine capable of streaming historical events from saved JSONL files. event logging
"""

import os
import sys
import json
import time
import base64
import hashlib
import socket
import select
from threading import Thread, Lock
from typing import Dict, List, Optional, Callable

# RFC 6455 WebSocket Magic GUID
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

class TelemetryEmitter:
    """
    Manages JSONL logging and real-time WebSocket distribution.
    """
    def __init__(self, log_path: str = "events.jsonl", ws_port: int = 8765):
        self.log_path = log_path
        self.ws_port = ws_port
        self._lock = Lock()
        self._clients: List[socket.socket] = []
        self._running = False
        self._server_sock: Optional[socket.socket] = None

    def start(self):
        """Starts WebSocket server background listener."""
        self._running = True
        t = Thread(target=self._ws_server_loop, daemon=True)
        t.start()

    def stop(self):
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass

    def emit(self, event_type: str, data: Dict):
        """
        Emits an event: writes to JSONL file and broadcasts to active WebSocket clients.
        Event types: 'bind', 'rotation', 'alert', 'expiry'.
        """
        record = {
            "ts": time.time(),
            "iso_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "type": event_type,
            **data
        }
        line = json.dumps(record)

        # 1. Write to JSONL
        with self._lock:
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception:
                pass
            if self.log_path != "/tmp/events.jsonl":
                try:
                    with open("/tmp/events.jsonl", "a", encoding="utf-8") as f2:
                        f2.write(line + "\n")
                except Exception:
                    pass

        # 2. Broadcast to WebSocket clients
        self.broadcast_ws(line)

    def broadcast_ws(self, text_payload: str):
        """Encodes and broadcasts text payload to connected WebSocket clients."""
        frame = self._encode_ws_text_frame(text_payload)
        with self._lock:
            disconnected = []
            for client in self._clients:
                try:
                    client.sendall(frame)
                except Exception:
                    disconnected.append(client)
            for d in disconnected:
                self._clients.remove(d)
                try:
                    d.close()
                except Exception:
                    pass

    @staticmethod
    def _encode_ws_text_frame(message: str) -> bytes:
        """Encodes string into an RFC 6455 unmasked text frame."""
        payload = message.encode("utf-8")
        length = len(payload)
        header = bytearray([0x81])  # FIN=1, Opcode=0x1 (Text)

        if length <= 125:
            header.append(length)
        elif length <= 65535:
            header.append(126)
            header.extend(length.to_bytes(2, byteorder="big"))
        else:
            header.append(127)
            header.extend(length.to_bytes(8, byteorder="big"))

        return bytes(header) + payload

    def _ws_server_loop(self):
        """Lightweight non-blocking RFC 6455 WebSocket listener."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", self.ws_port))
            sock.listen(5)
            sock.setblocking(False)
            self._server_sock = sock
        except Exception as e:
            # Port might be in use or restricted
            return

        while self._running:
            try:
                readable, _, _ = select.select([sock], [], [], 0.5)
                if not readable:
                    continue
                client, addr = sock.accept()
                self._handle_client_handshake(client)
            except Exception:
                pass

    def _handle_client_handshake(self, client: socket.socket):
        """Performs RFC 6455 HTTP upgrade handshake."""
        try:
            client.settimeout(2.0)
            data = client.recv(2048).decode("utf-8", errors="ignore")
            headers = {}
            for line in data.split("\r\n")[1:]:
                if ": " in line:
                    k, v = line.split(": ", 1)
                    headers[k.strip().lower()] = v.strip()

            sec_key = headers.get("sec-websocket-key")
            if not sec_key:
                client.close()
                return

            accept_val = base64.b64encode(
                hashlib.sha1((sec_key + WS_GUID).encode("utf-8")).digest()
            ).decode("utf-8")

            response = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept_val}\r\n\r\n"
            )
            client.sendall(response.encode("utf-8"))
            client.setblocking(False)
            with self._lock:
                self._clients.append(client)
        except Exception:
            try:
                client.close()
            except Exception:
                pass


# ==============================================================================
# REPLAY ENGINE
# ==============================================================================

def replay_events(
    jsonl_path: str,
    speed: float = 1.0,
    callback: Optional[Callable[[Dict], None]] = None,
    ws_emitter: Optional[TelemetryEmitter] = None
):
    """
    Replays historical events from a JSONL file, preserving relative timing.
    """
    if not os.path.exists(jsonl_path):
        print(f"[-] Replay file not found: {jsonl_path}")
        return

    print(f"[*] Replaying events from {jsonl_path} (speed = {speed}x)...")
    events = []
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except Exception:
                    pass

    if not events:
        print("[!] No events found in file.")
        return

    first_ts = events[0].get("ts", 0)
    sim_start = time.time()

    for ev in events:
        ev_ts = ev.get("ts", first_ts)
        rel_time = (ev_ts - first_ts) / max(0.01, speed)
        elapsed = time.time() - sim_start

        if rel_time > elapsed:
            time.sleep(rel_time - elapsed)

        # Output event
        ev_type = ev.get("type", "UNKNOWN").upper()
        p = ev.get("pseudonym", "NONE")
        print(f"[REPLAY] [{ev.get('iso_time', 'N/A')}] {ev_type:<8} P={p:<9} {json.dumps(ev)}")

        if callback:
            callback(ev)
        if ws_emitter:
            ws_emitter.broadcast_ws(json.dumps(ev))

    print("[+] Replay completed successfully.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="PS-007 Telemetry & Event Replay Tool")
    parser.add_argument("--replay", metavar="FILE", help="Path to JSONL file to replay")
    parser.add_argument("--speed", type=float, default=1.0, help="Replay speed multiplier")
    parser.add_argument("--ws-port", type=int, default=8765, help="WebSocket broadcast port")
    args = parser.parse_args()

    if args.replay:
        emitter = TelemetryEmitter(ws_port=args.ws_port)
        emitter.start()
        replay_events(args.replay, speed=args.speed, ws_emitter=emitter)
        time.sleep(1)
        emitter.stop()
    else:
        print("Running TelemetryEmitter test...")
        emitter = TelemetryEmitter("test_events.jsonl", ws_port=args.ws_port)
        emitter.start()
        emitter.emit("bind", {"pseudonym": "IOT-TEST", "addr": "fd00:abcd::1001"})
        emitter.emit("rotation", {"pseudonym": "IOT-TEST", "old_addr": "fd00:abcd::1001", "new_addr": "fd00:abcd::1002"})
        emitter.emit("alert", {"alert_type": "ROGUE_RA_TEST", "severity": "HIGH"})
        emitter.emit("expiry", {"pseudonym": "IOT-TEST", "reason": "TTL_EXPIRED"})
        print(f"Emitted test events to test_events.jsonl")
        replay_events("test_events.jsonl", speed=5.0)
        os.remove("test_events.jsonl")
        emitter.stop()
