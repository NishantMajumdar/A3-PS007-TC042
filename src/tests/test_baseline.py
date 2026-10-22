#!/usr/bin/env python3
"""
Unit test comparing BaselineDetector vs NDPAbuseDetector on rotating-source attacks.
"""

import unittest
import time
from baseline_detector import BaselineDetector
from detectors import NDPAbuseDetector

class TestBaselineComparison(unittest.TestCase):
    def test_rotating_source_evasion_against_baseline(self):
        """
        Demonstrates that rotating source IP evades naive per-IP detection,
        while pseudonym-anchored detection catches the attack.
        """
        baseline = BaselineDetector(rate_limit_pps=6.0, window_seconds=2.0)
        ndp_pseudonym = NDPAbuseDetector(hysteresis_n=3, hysteresis_m=5)

        t0 = time.time()
        pseudonym = "IOT-ATTACKER"
        baseline_alerts = 0
        pseudonym_alerts = 0

        # Attacker sends 20 packets at 10 pps, but rotates source IP every 4 packets (every 0.4s)
        for i in range(20):
            current_t = t0 + (i * 0.1)
            # IP rotates every 4 packets
            ip_generation = i // 4
            src_ip = f"fd00:abcd::{ip_generation:04x}"

            # 1. Baseline inspection
            b_alert = baseline.process_packet(src_ip, current_time=current_t)
            if b_alert:
                baseline_alerts += 1

            # 2. Pseudonym inspection (attributed to same link anchor/pseudonym)
            p_alerts = ndp_pseudonym.record_ndp_packet(
                pseudonym=pseudonym,
                ndp_type="NS",
                src_ip=src_ip,
                target_ip="fd00:abcd::1",
                current_time=current_t
            )
            if p_alerts:
                pseudonym_alerts += len(p_alerts)

        # Baseline failed to detect due to IP rotation (never exceeded threshold per single IP)
        self.assertEqual(baseline_alerts, 0, "Naive baseline must fail to detect rotating-source attack.")
        # Pseudonym detector successfully caught the attack
        self.assertGreater(pseudonym_alerts, 0, "Pseudonym detector must catch rotating-source attack.")

if __name__ == "__main__":
    unittest.main()
