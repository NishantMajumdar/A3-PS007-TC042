"""
optional_mode_b - Optional Active Agent & Cryptographic Ratchet Extension for PS-007

Mode A is the PRIMARY monitoring mode (Zero-agent, pure black-box IoT tracking via
mirrored DAD Neighbor Solicitations and VLAN link anchors).

Mode B is STRICTLY OPTIONAL for scenarios where IoT endpoints are fully managed devices
capable of executing a local client agent and running a cryptographic hash ratchet.
"""

from .ratchet import ratchet_step, compute_ratchet_tag, verify_ratchet_update

__all__ = [
    "ratchet_step",
    "compute_ratchet_tag",
    "verify_ratchet_update",
]
