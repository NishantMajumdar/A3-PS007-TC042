#!/usr/bin/env python3
"""
Unit tests for monitor.py packet processing, verifying rogue RA handling and non-crashing behavior.
"""

import unittest
from scapy.all import Dot1Q, IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo

import monitor

class TestMonitorPacketProcessing(unittest.TestCase):
    def setUp(self):
        monitor.session_records.clear()
        monitor.ip_to_session.clear()
        monitor.unauthenticated_devices.clear()
        monitor.recent_security_alerts.clear()
        monitor.latest_events.clear()

    def test_rogue_ra_packet_handling_does_not_crash(self):
        """Simulate an attacker on client port 4 (wire VLAN 8) sending a rogue RA."""
        fake_ra = (
            Dot1Q(vlan=8) /
            IPv6(src="fd00:abcd::dead:beef", dst="ff02::1", hlim=255) /
            ICMPv6ND_RA(routerlifetime=1800, chlim=64, M=1, O=1) /
            ICMPv6NDOptPrefixInfo(prefix="2001:db8:dead::", prefixlen=64, validlifetime=3600, preferredlifetime=1800)
        )

        # Must not raise an exception
        monitor.process_packet(fake_ra)

        # Verify session attribution and rogue attacker status
        sid = "SES-PORT04"
        self.assertIn(sid, monitor.session_records)
        record = monitor.session_records[sid]
        self.assertEqual(record["status"], "ROGUE ATTACKER")
        self.assertTrue(record["is_rogue"])
        self.assertEqual(len(record["pseudonym"]), 8)

        # Verify alert was generated
        self.assertTrue(len(monitor.recent_security_alerts) > 0)
        alert = monitor.recent_security_alerts[0][1]
        self.assertIn("ROGUE_RA", alert.alert_type)
        self.assertEqual(alert.pseudonym, record["pseudonym"])

        # Verify auto-quarantine isolated port 4
        self.assertTrue(record.get("quarantined"))
        self.assertEqual(record.get("quarantine_port"), 4)
        self.assertIn(4, monitor.quarantined_ports)

    def test_rogue_ra_arbitrary_port_8_does_not_crash(self):
        """Simulate an attacker on port 8 (wire VLAN 12, or 4108) sending rogue RA."""
        fake_ra = (
            Dot1Q(vlan=12) /
            IPv6(src="fd00:abcd::cafe:1234", dst="ff02::1", hlim=255) /
            ICMPv6ND_RA(routerlifetime=0, chlim=64) /
            ICMPv6NDOptPrefixInfo(prefix="fd00:abcd::", prefixlen=64, validlifetime=0, preferredlifetime=0)
        )

        # Must not raise an exception
        monitor.process_packet(fake_ra)

        sid = "SES-PORT08"
        self.assertIn(sid, monitor.session_records)
        record = monitor.session_records[sid]
        self.assertEqual(record["status"], "ROGUE ATTACKER")
        self.assertTrue(record["is_rogue"])
        self.assertTrue(record.get("quarantined"))
        self.assertEqual(record.get("quarantine_port"), 8)
        self.assertIn(8, monitor.quarantined_ports)

    def test_infrastructure_ports_never_quarantined(self):
        """Verify that port 1 (router) and port 2 (monitor) can never be quarantined."""
        self.assertFalse(monitor.quarantine_switch_port(1, "test router"))
        self.assertFalse(monitor.quarantine_switch_port(2, "test monitor"))
        self.assertNotIn(1, monitor.quarantined_ports)
        self.assertNotIn(2, monitor.quarantined_ports)

    def test_router_port_1_ndp_not_flagged_as_attacker(self):
        """Verify router r1 (port 1 / wire VLAN 5) resolving client targets is not flagged as attacker."""
        from scapy.all import ICMPv6ND_NS
        init_pkts = monitor.router_record["pkts"]

        # Simulate router querying 6 different client IPs
        for i in range(1, 7):
            router_ns = (
                Dot1Q(vlan=5) /
                IPv6(src="fe80::147f:45ff:fef5:4905", dst="ff02::1:ff00:1", hlim=255) /
                ICMPv6ND_NS(tgt=f"fd00:abcd::{i}")
            )
            monitor.process_packet(router_ns)

        # Port 1 / Gateway MUST NOT be placed into client session_records
        self.assertNotIn("SES-PORT01", monitor.session_records)
        self.assertEqual(len(monitor.session_records), 0)

        # Router record packets counter should have increased
        self.assertEqual(monitor.router_record["pkts"], init_pkts + 6)

        # No alerts should have been generated
        self.assertEqual(len(monitor.recent_security_alerts), 0)
