#!/usr/bin/env python3
"""
Unit tests for pseudonym.py
Compatible with both pytest and python -m unittest.
"""

import unittest
import time
from pseudonym import PseudonymManager, ExpiredPseudonymError

class TestPseudonymManager(unittest.TestCase):
    def setUp(self):
        # 10s epoch, 2s address TTL, 5s hard session TTL for rapid testing
        self.mgr = PseudonymManager(
            epoch_length_seconds=10.0,
            default_addr_ttl=2.0,
            default_hard_session_ttl=5.0
        )

    def test_pseudonym_generation_and_length(self):
        session, p1 = self.mgr.get_or_create_session("tenant-A", "session-001", "vlan-4103")
        self.assertIsNotNone(p1)
        self.assertEqual(len(p1), 8)
        # Identical request in same epoch should return identical pseudonym
        session2, p2 = self.mgr.get_or_create_session("tenant-A", "session-001", "vlan-4103")
        self.assertEqual(p1, p2)

    def test_cross_tenant_isolation(self):
        # Same session_id in two different tenants MUST yield different pseudonyms
        _, p_a = self.mgr.get_or_create_session("tenant-A", "shared-id", "vlan-4103")
        _, p_b = self.mgr.get_or_create_session("tenant-B", "shared-id", "vlan-4103")
        self.assertNotEqual(p_a, p_b)

        # Bind address in tenant-A
        self.mgr.bind_address("tenant-A", "shared-id", "fd00:abcd::10")
        
        # Lookup in tenant-A succeeds
        self.assertEqual(self.mgr.lookup_pseudonym_by_addr("tenant-A", "fd00:abcd::10"), p_a)
        
        # Lookup in tenant-B MUST fail (return None)
        self.assertIsNone(self.mgr.lookup_pseudonym_by_addr("tenant-B", "fd00:abcd::10"))

    def test_address_binding_ttl_expiry(self):
        self.mgr.get_or_create_session("tenant-A", "dev-1", "vlan-4103")
        p = self.mgr.bind_address("tenant-A", "dev-1", "fd00:abcd::20", ttl_seconds=1.0)
        
        # Immediate lookup succeeds
        self.assertEqual(self.mgr.lookup_pseudonym_by_addr("tenant-A", "fd00:abcd::20"), p)
        
        # Simulate time passing beyond TTL (1.5s)
        now = time.time() + 1.5
        self.assertIsNone(self.mgr.lookup_pseudonym_by_addr("tenant-A", "fd00:abcd::20", current_time=now))

    def test_hard_session_ttl_expiry(self):
        # Session with 2s hard TTL
        self.mgr.get_or_create_session("tenant-A", "dev-hard", "vlan-4104", hard_ttl_seconds=2.0)
        p = self.mgr.bind_address("tenant-A", "dev-hard", "fd00:abcd::30")
        
        # Before hard TTL expiry
        self.assertEqual(self.mgr.lookup_pseudonym_by_addr("tenant-A", "fd00:abcd::30"), p)
        
        # After hard TTL expiry (3s)
        now = time.time() + 3.0
        self.assertIsNone(self.mgr.lookup_pseudonym_by_addr("tenant-A", "fd00:abcd::30", current_time=now))
        self.assertIsNone(self.mgr.lookup_session_by_pseudonym("tenant-A", p, current_time=now))

    def test_epoch_rotation_and_key_overwrite(self):
        # Capture old key reference
        old_k_bytes = bytes(self.mgr._k_epoch)
        _, p_epoch1 = self.mgr.get_or_create_session("tenant-A", "session-rot", "vlan-4105")
        
        # Rotate epoch
        self.mgr.rotate_epoch()
        
        # Verify old key array in memory was overwritten
        new_k_bytes = bytes(self.mgr._k_epoch)
        self.assertNotEqual(old_k_bytes, new_k_bytes)
        
        # Same session in new epoch MUST have a different pseudonym (no cross-epoch linkage)
        _, p_epoch2 = self.mgr.get_or_create_session("tenant-A", "session-rot", "vlan-4105")
        self.assertNotEqual(p_epoch1, p_epoch2)

    def test_purge_function(self):
        self.mgr.get_or_create_session("tenant-A", "dev-purge", "vlan-4106", hard_ttl_seconds=2.0)
        self.mgr.bind_address("tenant-A", "dev-purge", "fd00:abcd::50", ttl_seconds=1.0)
        
        # Purge after 3s
        stats = self.mgr.purge(current_time=time.time() + 3.0)
        self.assertGreaterEqual(stats["purged_addrs"], 1)
        self.assertGreaterEqual(stats["purged_sessions"], 1)

if __name__ == "__main__":
    unittest.main()
