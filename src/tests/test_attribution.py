#!/usr/bin/env python3
"""
Unit tests for attribution.py
Tests DAD validation, bounded allowance per rotation, and pseudonym binding.
"""

import unittest
import time
from scapy.all import Dot1Q, IPv6, ICMPv6ND_NS, Ether
from pseudonym import PseudonymManager
from attribution import AttributionEngine

class TestAttributionEngine(unittest.TestCase):
    def setUp(self):
        self.pm = PseudonymManager(epoch_length_seconds=300.0, default_addr_ttl=60.0)
        self.engine = AttributionEngine(
            pseudonym_manager=self.pm,
            expected_prefix="fd00:abcd::/64",
            max_bindings_per_rotation=2,     # bounded allowance: max 2 bindings
            rotation_window_seconds=10.0      # 10s rotation window for rapid tests
        )

    def test_valid_dad_ns_binding(self):
        """Valid DAD NS with src :: and valid tentative target binds successfully."""
        event = self.engine.handle_dad_ns(
            vlan_id=4103,
            target_ip="fd00:abcd::1001",
            ipv6_src="::",
            ipv6_dst="ff02::1:ff00:1001",
            hop_limit=255
        )
        self.assertEqual(event.event_type, "BIND_DAD")
        self.assertIsNotNone(event.pseudonym)
        self.assertEqual(len(event.pseudonym), 8)
        self.assertEqual(event.session_id, "SES-PORT03")

        # Verify pseudonym lookup for this address now succeeds in manager
        p_lookup = self.pm.lookup_pseudonym_by_addr("default", "fd00:abcd::1001")
        self.assertEqual(p_lookup, event.pseudonym)

    def test_invalid_dad_ns_rejected(self):
        """DAD NS with non-:: source or invalid hop limit is rejected."""
        # Invalid source IP
        ev1 = self.engine.handle_dad_ns(
            vlan_id=4103,
            target_ip="fd00:abcd::1002",
            ipv6_src="fd00:abcd::9999",
            hop_limit=255
        )
        self.assertEqual(ev1.event_type, "REJECT_INVALID_DAD")

        # Invalid hop limit (< 255)
        ev2 = self.engine.handle_dad_ns(
            vlan_id=4103,
            target_ip="fd00:abcd::1003",
            ipv6_src="::",
            hop_limit=64
        )
        self.assertEqual(ev2.event_type, "REJECT_INVALID_DAD")

        # Target outside subnet
        ev3 = self.engine.handle_dad_ns(
            vlan_id=4103,
            target_ip="2001:db8::1",
            ipv6_src="::",
            hop_limit=255
        )
        self.assertEqual(ev3.event_type, "REJECT_INVALID_DAD")

    def test_bounded_allowance_per_rotation(self):
        """Verify that bindings exceeding max_bindings_per_rotation are rejected."""
        t_base = time.time()

        # 1st binding: allowed (1/2)
        ev1 = self.engine.handle_dad_ns(
            vlan_id=4104,
            target_ip="fd00:abcd::2001",
            current_time=t_base
        )
        self.assertEqual(ev1.event_type, "BIND_DAD")

        # 2nd binding: allowed (2/2)
        ev2 = self.engine.handle_dad_ns(
            vlan_id=4104,
            target_ip="fd00:abcd::2002",
            current_time=t_base + 1.0
        )
        self.assertEqual(ev2.event_type, "BIND_DAD")

        # 3rd binding within window: REJECTED (exceeded allowance)
        ev3 = self.engine.handle_dad_ns(
            vlan_id=4104,
            target_ip="fd00:abcd::2003",
            current_time=t_base + 2.0
        )
        self.assertEqual(ev3.event_type, "REJECT_EXCEEDED")

        # Address 3rd was NOT bound
        self.assertIsNone(self.pm.lookup_pseudonym_by_addr("default", "fd00:abcd::2003"))

        # Advance past rotation window (11s later): new rotation window opens
        ev4 = self.engine.handle_dad_ns(
            vlan_id=4104,
            target_ip="fd00:abcd::2004",
            current_time=t_base + 12.0
        )
        self.assertEqual(ev4.event_type, "BIND_DAD")

    def test_raw_scapy_packet_processing_and_mac_drop(self):
        """Processes Scapy packet, strips Dot1Q vlan_id, and drops Ether.src."""
        # Construct mirrored Scapy packet with Dot1Q
        pkt = Ether(src="aa:bb:cc:dd:ee:ff", dst="33:33:00:00:00:01") / \
              Dot1Q(vlan=4105) / \
              IPv6(src="::", dst="ff02::1", hlim=255) / \
              ICMPv6ND_NS(tgt="fd00:abcd::3001")

        event = self.engine.process_raw_scapy_packet(pkt)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "BIND_DAD")
        self.assertEqual(event.vlan_id, 4105)
        self.assertEqual(event.target_addr, "fd00:abcd::3001")

        # Confirm Ether layer was not stored in event
        ev_dict = event.to_dict()
        self.assertNotIn("src_mac", ev_dict)
        self.assertNotIn("mac", ev_dict)

if __name__ == "__main__":
    unittest.main()
