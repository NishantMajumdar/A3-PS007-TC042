#!/usr/bin/env python3
"""
Unit tests for detectors.py (Rogue RA and NDP Abuse detectors).
"""

import unittest
import time
from detectors import RogueRADetector, NDPAbuseDetector

class TestDetectors(unittest.TestCase):
    def setUp(self):
        self.ra_detector = RogueRADetector(
            authorized_routers=["fd00:abcd::1"],
            authorized_prefix="fd00:abcd::",
            authorized_prefix_len=64,
            expected_hop_limit=64,
            burst_threshold=3,
            burst_window_seconds=1.0
        )
        self.ndp_detector = NDPAbuseDetector(
            hysteresis_n=3,
            hysteresis_m=5,
            max_distinct_targets=3,
            target_window_seconds=5.0
        )

    def test_legitimate_ra_no_alerts(self):
        alerts = self.ra_detector.inspect_ra(
            src_ip="fd00:abcd::1",
            router_lifetime=1800,
            cur_hop_limit=64,
            managed_flag=0,
            other_flag=0,
            advertised_prefixes=[("fd00:abcd::", 64)]
        )
        self.assertEqual(len(alerts), 0)

    def test_rogue_ra_unauthorized_source(self):
        alerts = self.ra_detector.inspect_ra(
            src_ip="fd00:abcd::666",
            router_lifetime=1800,
            cur_hop_limit=64,
            managed_flag=0,
            other_flag=0,
            advertised_prefixes=[("fd00:abcd::", 64)]
        )
        types = [a.alert_type for a in alerts]
        self.assertIn("ROGUE_RA_UNAUTHORIZED_SOURCE", types)

    def test_router_vlan_dynamic_link_local_learning(self):
        # Router r1 sends RA with link-local src from wire VLAN 5 (4101 % 4096)
        alerts = self.ra_detector.inspect_ra(
            src_ip="fe80::79:72ff:fefa:11fa",
            router_lifetime=1800,
            cur_hop_limit=64,
            managed_flag=0,
            other_flag=0,
            advertised_prefixes=[("fd00:abcd::", 64)],
            vlan_id=5
        )
        self.assertEqual(len(alerts), 0)
        self.assertIn("fe80::79:72ff:fefa:11fa", self.ra_detector.authorized_routers)

    def test_rogue_ra_on_client_port_rejected(self):
        # Host on client port (vlan 8 / h2) attempts to send RA
        alerts = self.ra_detector.inspect_ra(
            src_ip="fe80::dead:beef",
            router_lifetime=1800,
            cur_hop_limit=64,
            managed_flag=0,
            other_flag=0,
            advertised_prefixes=[("fd00:abcd::", 64)],
            vlan_id=8
        )
        types = [a.alert_type for a in alerts]
        self.assertIn("ROGUE_RA_UNAUTHORIZED_SOURCE", types)

    def test_rogue_ra_lifetime_zero_dos(self):
        alerts = self.ra_detector.inspect_ra(
            src_ip="fd00:abcd::1",
            router_lifetime=0,
            cur_hop_limit=64,
            managed_flag=0,
            other_flag=0,
            advertised_prefixes=[("fd00:abcd::", 64)]
        )
        types = [a.alert_type for a in alerts]
        self.assertIn("ROGUE_RA_ZERO_LIFETIME", types)

    def test_rogue_ra_unexpected_prefix(self):
        alerts = self.ra_detector.inspect_ra(
            src_ip="fd00:abcd::1",
            router_lifetime=1800,
            cur_hop_limit=64,
            managed_flag=0,
            other_flag=0,
            advertised_prefixes=[("2001:db8::", 64)]
        )
        types = [a.alert_type for a in alerts]
        self.assertIn("ROGUE_RA_UNEXPECTED_PREFIX", types)

    def test_rogue_ra_burst_alert(self):
        t0 = time.time()
        # 3 RAs in 0.2s
        self.ra_detector.inspect_ra("fd00:abcd::1", 1800, 64, 0, 0, [("fd00:abcd::", 64)], current_time=t0)
        self.ra_detector.inspect_ra("fd00:abcd::1", 1800, 64, 0, 0, [("fd00:abcd::", 64)], current_time=t0 + 0.1)
        alerts = self.ra_detector.inspect_ra("fd00:abcd::1", 1800, 64, 0, 0, [("fd00:abcd::", 64)], current_time=t0 + 0.2)
        types = [a.alert_type for a in alerts]
        self.assertIn("ROGUE_RA_BURST", types)

    def test_ndp_normal_traffic_within_token_bucket(self):
        t0 = time.time()
        alerts = []
        for i in range(3):
            res = self.ndp_detector.record_ndp_packet(
                pseudonym="IOT-0001",
                ndp_type="NS",
                src_ip="fd00:abcd::10",
                target_ip="fd00:abcd::1",
                current_time=t0 + (i * 0.5)
            )
            alerts.extend(res)
        self.assertEqual(len(alerts), 0)

    def test_ndp_flood_hysteresis_alert(self):
        t0 = time.time()
        all_alerts = []
        # Rapidly exhaust bucket and exceed hysteresis (10 rapid NS packets)
        for i in range(12):
            res = self.ndp_detector.record_ndp_packet(
                pseudonym="IOT-ATTACK",
                ndp_type="NS",
                src_ip="fd00:abcd::99",
                target_ip="fd00:abcd::1",
                current_time=t0 + (i * 0.05)
            )
            all_alerts.extend(res)

        types = [a.alert_type for a in all_alerts]
        self.assertIn("NDP_RATE_ABUSE_HYSTERESIS", types)

    def test_ndp_target_scanning_cardinality_alert(self):
        t0 = time.time()
        all_alerts = []
        # Query 5 distinct targets within 1 second
        for i in range(5):
            res = self.ndp_detector.record_ndp_packet(
                pseudonym="IOT-SCANNER",
                ndp_type="NS",
                src_ip="fd00:abcd::55",
                target_ip=f"fd00:abcd::{i+100:04x}",
                current_time=t0 + (i * 0.1)
            )
            all_alerts.extend(res)

        types = [a.alert_type for a in all_alerts]
        self.assertIn("NDP_SCAN_CARDINALITY_ALERT", types)

    def test_per_pseudonym_state_purge_on_expiry(self):
        p = "IOT-EXPIRING"
        self.ndp_detector.record_ndp_packet(p, "NS", "fd00:abcd::1", "fd00:abcd::2")
        self.assertIn(p, self.ndp_detector._states)

        # Delete pseudonym state
        self.ndp_detector.delete_pseudonym_state(p)
        self.assertNotIn(p, self.ndp_detector._states)

if __name__ == "__main__":
    unittest.main()
