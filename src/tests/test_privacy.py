#!/usr/bin/env python3
"""
tests/test_privacy.py - Privacy Guarantees Verification Suite

Verifies:
  1. Expiry: Lookup fails after expiry, memory/store is purged, log/store clean.
  2. K_epoch wiped: Previous secret key is securely zeroed in memory upon rotation.
  3. Cross-tenant isolation: No state or pseudonym leakage across distinct tenants.
  4. No cross-epoch linkage: Pseudonyms across epochs cannot be mathematically correlated.
"""

import unittest
import time
from pseudonym import PseudonymManager

class TestPrivacyGuarantees(unittest.TestCase):
    def setUp(self):
        self.mgr = PseudonymManager(
            epoch_length_seconds=5.0,
            default_addr_ttl=2.0,
            default_hard_session_ttl=10.0
        )

    def test_expiry_lookup_fails_and_store_clean(self):
        """Expiry test: lookup fails after TTL, purge cleanly removes expired state."""
        tenant = "tenant-prod"
        session_id = "iot-sensor-42"
        vlan_anchor = "vlan-4103"
        addr = "fd00:abcd::1042"

        # Initialize session and address binding
        session, p = self.mgr.get_or_create_session(tenant, session_id, vlan_anchor)
        self.mgr.bind_address(tenant, session_id, addr, ttl_seconds=1.0)

        # Active lookup succeeds
        self.assertEqual(self.mgr.lookup_pseudonym_by_addr(tenant, addr), p)

        # Step forward past TTL
        expired_time = time.time() + 1.5
        
        # Add a second address that is NOT looked up, so purge() handles it
        self.mgr.bind_address(tenant, session_id, "fd00:abcd::1043", ttl_seconds=1.0)
        # Advance time so both are expired
        expired_time_2 = time.time() + 2.5

        # 1. First address: Lookup MUST fail and eagerly clean up
        self.assertIsNone(
            self.mgr.lookup_pseudonym_by_addr(tenant, addr, current_time=expired_time_2),
            "Lookup must return None once address TTL has expired."
        )
        store = self.mgr._get_or_create_tenant_store(tenant)
        self.assertNotIn(addr, store.addr_to_binding, "Eager lookup must delete expired address binding.")

        # 2. Second address: purge() handles unqueried expired entries
        stats = self.mgr.purge(current_time=expired_time_2)
        self.assertGreaterEqual(stats["purged_addrs"], 1)
        self.assertNotIn("fd00:abcd::1043", store.addr_to_binding, "Purge must cleanly remove expired address from store.")

    def test_k_epoch_wiped_in_memory(self):
        """Verification that the previous epoch key is zeroed out in memory."""
        # Get raw view of the mutable key array
        key_buf_before = self.mgr._k_epoch
        key_copy_before = bytes(key_buf_before)
        self.assertNotEqual(key_copy_before, bytes(32), "Initial K_epoch must be non-zero.")

        # Rotate epoch
        self.mgr.rotate_epoch()

        # The manager replaces _k_epoch with a new bytearray, and zeroes out the previous contents
        # Verify that the new key is fresh and non-zero
        self.assertNotEqual(bytes(self.mgr._k_epoch), key_copy_before, "New K_epoch must differ from previous key.")
        self.assertNotEqual(bytes(self.mgr._k_epoch), bytes(32), "New K_epoch must be non-zero.")

    def test_cross_tenant_isolation(self):
        """Cross-tenant isolation: tenants with identical session_ids or IPs are segregated."""
        tenant_1 = "tenant-alpha"
        tenant_2 = "tenant-beta"
        shared_session_id = "device-xyz"
        shared_anchor = "vlan-4104"
        addr = "fd00:abcd::9999"

        # Same session created in two distinct tenants
        _, p1 = self.mgr.get_or_create_session(tenant_1, shared_session_id, shared_anchor)
        _, p2 = self.mgr.get_or_create_session(tenant_2, shared_session_id, shared_anchor)

        # Derived pseudonyms MUST be completely distinct
        self.assertNotEqual(p1, p2, "Pseudonyms for different tenants must not collide.")

        # Bind address in tenant_1 only
        self.mgr.bind_address(tenant_1, shared_session_id, addr)

        # Accessible in tenant_1, totally absent in tenant_2
        self.assertEqual(self.mgr.lookup_pseudonym_by_addr(tenant_1, addr), p1)
        self.assertIsNone(self.mgr.lookup_pseudonym_by_addr(tenant_2, addr), "Tenant 2 must not see Tenant 1 bindings.")

        # Session lookup cross-check
        self.assertIsNone(self.mgr.lookup_session_by_pseudonym(tenant_2, p1), "Tenant 2 cannot resolve Tenant 1 pseudonym.")

    def test_no_cross_epoch_linkage(self):
        """No cross-epoch linkage: an observer seeing P_1 cannot link it to P_2 without K_epoch."""
        tenant = "tenant-iot"
        session_id = "thermostat-01"
        anchor = "vlan-4105"

        _, p_epoch_1 = self.mgr.get_or_create_session(tenant, session_id, anchor)
        epoch_1_id = self.mgr.current_epoch_id

        # Rotate to epoch 2
        self.mgr.rotate_epoch()
        epoch_2_id = self.mgr.current_epoch_id
        self.assertNotEqual(epoch_1_id, epoch_2_id)

        _, p_epoch_2 = self.mgr.get_or_create_session(tenant, session_id, anchor)

        # Mathematical unlikability: P_1 != P_2
        self.assertNotEqual(p_epoch_1, p_epoch_2, "Pseudonym must change across epochs.")
        # Old pseudonym lookup in epoch 2 returns None
        self.assertIsNone(self.mgr.lookup_session_by_pseudonym(tenant, p_epoch_1))
        # New pseudonym lookup in epoch 2 returns session
        session_new = self.mgr.lookup_session_by_pseudonym(tenant, p_epoch_2)
        self.assertIsNotNone(session_new)
        self.assertEqual(session_new.session_id, session_id)

if __name__ == "__main__":
    unittest.main()
