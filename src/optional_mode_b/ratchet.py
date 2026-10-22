#!/usr/bin/env python3
"""
optional_mode_b/ratchet.py - Optional Mode B Cryptographic Key Ratchet & Replay Protection

Formulas:
  - Key Ratchet: S_{i+1} = H(S_i) = SHA256(S_i)
  - Tag: HMAC(S_i, new_addr || ctr)
  - Replay Protection: Strict rejection of non-increasing counters (ctr <= last_counter)

NOTE: Mode A is the primary black-box tracking engine. This module is used ONLY
when the optional Mode B active client agent is explicitly enabled.
"""

import hmac
import hashlib
from typing import Tuple

def ratchet_step(current_key: bytes) -> bytes:
    """Computes forward-secure key ratchet: S_{i+1} = SHA256(S_i)."""
    return hashlib.sha256(current_key).digest()

def compute_ratchet_tag(key: bytes, new_addr: str, counter: int) -> str:
    """Computes authentication tag: HMAC(S_i, new_addr || str(counter))."""
    payload = f"{new_addr}||{counter}".encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()

def verify_ratchet_update(
    current_key: bytes,
    last_counter: int,
    new_addr: str,
    counter: int,
    provided_tag: str
) -> Tuple[bool, str, bytes, int]:
    """
    Verifies incoming Mode B ratchet update from an active agent.
    Returns (is_valid, reason, next_key, next_counter).
    """
    # 1. Replay Protection: Counter must be strictly increasing
    if counter <= last_counter:
        return False, f"Replay detected: counter {counter} <= last_counter {last_counter}", current_key, last_counter

    # 2. Tag verification
    expected_tag = compute_ratchet_tag(current_key, new_addr, counter)
    if not hmac.compare_digest(expected_tag, provided_tag):
        return False, "Invalid HMAC tag for ratchet step", current_key, last_counter

    # 3. Advance ratchet
    next_key = ratchet_step(current_key)
    return True, "Valid ratchet update", next_key, counter
