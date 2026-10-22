#!/usr/bin/env python3
"""
ratchet.py - Backward Compatibility Shim for Optional Mode B

Mode B has been segregated into the `optional_mode_b/` package.
This module re-exports the Mode B ratchet functions for compatibility with any existing imports.
"""

from optional_mode_b.ratchet import (
    ratchet_step,
    compute_ratchet_tag,
    verify_ratchet_update,
)

__all__ = [
    "ratchet_step",
    "compute_ratchet_tag",
    "verify_ratchet_update",
]
