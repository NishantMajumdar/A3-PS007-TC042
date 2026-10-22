#!/usr/bin/env python3
"""
Unit tests for Mode B key ratchet and replay protection (tests/test_ratchet.py).
"""

import unittest
import os
from optional_mode_b.ratchet import ratchet_step, compute_ratchet_tag, verify_ratchet_update
import ratchet as root_ratchet

class TestKeyRatchet(unittest.TestCase):
    def setUp(self):
        self.initial_seed = os.urandom(32)

    def test_shim_exports(self):
        """Verifies root ratchet.py re-exports optional_mode_b functions identically."""
        self.assertIs(root_ratchet.ratchet_step, ratchet_step)
        self.assertIs(root_ratchet.compute_ratchet_tag, compute_ratchet_tag)
        self.assertIs(root_ratchet.verify_ratchet_update, verify_ratchet_update)


    def test_single_ratchet_step(self):
        k0 = self.initial_seed
        ctr = 1
        new_addr = "fd00:abcd::1001"
        tag = compute_ratchet_tag(k0, new_addr, ctr)

        # Server verifies update
        valid, msg, k1, next_ctr = verify_ratchet_update(
            current_key=k0,
            last_counter=0,
            new_addr=new_addr,
            counter=ctr,
            provided_tag=tag
        )
        self.assertTrue(valid)
        self.assertEqual(next_ctr, 1)
        self.assertEqual(k1, ratchet_step(k0))

    def test_replay_protection_counter_decrease_or_equal(self):
        k0 = self.initial_seed
        ctr = 5
        new_addr = "fd00:abcd::1002"
        tag = compute_ratchet_tag(k0, new_addr, ctr)

        # 1. First verification with counter 5 succeeds
        valid, _, k1, last_ctr = verify_ratchet_update(k0, 4, new_addr, ctr, tag)
        self.assertTrue(valid)
        self.assertEqual(last_ctr, 5)

        # 2. Replay with identical counter 5 MUST BE REJECTED
        valid_replay, reason, _, _ = verify_ratchet_update(k1, 5, new_addr, 5, tag)
        self.assertFalse(valid_replay)
        self.assertIn("Replay detected", reason)

        # 3. Replay with lower counter MUST BE REJECTED
        valid_lower, reason_lower, _, _ = verify_ratchet_update(k1, 5, new_addr, 3, tag)
        self.assertFalse(valid_lower)
        self.assertIn("Replay detected", reason_lower)

    def test_invalid_tag_rejected(self):
        k0 = self.initial_seed
        valid, msg, _, _ = verify_ratchet_update(
            current_key=k0,
            last_counter=0,
            new_addr="fd00:abcd::1003",
            counter=1,
            provided_tag="invaliddeadbeef00112233"
        )
        self.assertFalse(valid)
        self.assertIn("Invalid HMAC", msg)

    def test_multi_step_ratchet_chain(self):
        """Simulate 5 sequential address rotations with forward secrecy."""
        client_key = self.initial_seed
        server_key = self.initial_seed
        last_ctr = 0

        for step in range(1, 6):
            addr = f"fd00:abcd::{step:04x}"
            tag = compute_ratchet_tag(client_key, addr, step)
            client_key = ratchet_step(client_key)

            # Server verifies and advances
            valid, _, server_key, last_ctr = verify_ratchet_update(
                server_key, last_ctr, addr, step, tag
            )
            self.assertTrue(valid)
            self.assertEqual(last_ctr, step)
            self.assertEqual(client_key, server_key)

if __name__ == "__main__":
    unittest.main()
