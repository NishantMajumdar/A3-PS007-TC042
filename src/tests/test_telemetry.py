#!/usr/bin/env python3
"""
Unit tests for telemetry.py (JSONL emission, replay, and WebSocket framing).
"""

import os
import unittest
import json
from telemetry import TelemetryEmitter, replay_events

class TestTelemetry(unittest.TestCase):
    def setUp(self):
        self.log_file = "test_run_events.jsonl"
        if os.path.exists(self.log_file):
            os.remove(self.log_file)
        self.emitter = TelemetryEmitter(log_path=self.log_file, ws_port=18765)

    def tearDown(self):
        self.emitter.stop()
        if os.path.exists(self.log_file):
            os.remove(self.log_file)

    def test_jsonl_emission(self):
        """Emits all 4 event types and verifies JSONL format."""
        self.emitter.emit("bind", {"pseudonym": "IOT-0001", "addr": "fd00:abcd::1001", "vlan_id": 4103})
        self.emitter.emit("rotation", {"pseudonym": "IOT-0001", "old_addr": "fd00:abcd::1001", "new_addr": "fd00:abcd::1002"})
        self.emitter.emit("alert", {"alert_type": "ROGUE_RA_BURST", "severity": "HIGH", "src": "fd00:abcd::dead"})
        self.emitter.emit("expiry", {"pseudonym": "IOT-0001", "reason": "TTL_EXPIRED"})

        self.assertTrue(os.path.exists(self.log_file))
        records = []
        with open(self.log_file, "r") as f:
            for line in f:
                records.append(json.loads(line.strip()))

        self.assertEqual(len(records), 4)
        types = [r["type"] for r in records]
        self.assertEqual(types, ["bind", "rotation", "alert", "expiry"])
        self.assertEqual(records[0]["pseudonym"], "IOT-0001")
        self.assertEqual(records[2]["alert_type"], "ROGUE_RA_BURST")

    def test_replay_events(self):
        """Verifies replay reads and delivers all events."""
        self.emitter.emit("bind", {"pseudonym": "P-AAA", "addr": "fd00:abcd::1"})
        self.emitter.emit("alert", {"alert_type": "NDP_ABUSE", "severity": "CRITICAL"})

        received = []
        def on_event(ev):
            received.append(ev)

        replay_events(self.log_file, speed=100.0, callback=on_event)
        self.assertEqual(len(received), 2)
        self.assertEqual(received[0]["pseudonym"], "P-AAA")
        self.assertEqual(received[1]["alert_type"], "NDP_ABUSE")

    def test_ws_text_frame_encoding(self):
        """Verifies RFC 6455 unmasked text frame encoding."""
        frame = TelemetryEmitter._encode_ws_text_frame("PING")
        self.assertEqual(frame[0], 0x81)  # FIN=1, Text Opcode
        self.assertEqual(frame[1], 4)     # Payload length 4
        self.assertEqual(frame[2:], b"PING")

if __name__ == "__main__":
    unittest.main()
