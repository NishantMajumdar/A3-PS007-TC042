#!/usr/bin/env python3
"""
baseline_detector.py - Naive Per-Source-IP Rate Limiter (Baseline Comparison)

This module represents traditional IPv6 security monitoring that naively tracks
packet counts per source IPv6 address (IPv6.src). Because RFC 8981 clients and
adversaries continuously rotate their temporary IPv6 addresses, per-IP counters
reset on every rotation, causing severe detection blindness (low TPR / high FNR).
"""

import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple

class BaselineAlert:
    def __init__(self, alert_type: str, src_ip: str, pps: float, threshold: float, timestamp: float = None):
        self.alert_type = alert_type
        self.src_ip = src_ip
        self.pps = pps
        self.threshold = threshold
        self.timestamp = timestamp if timestamp is not None else time.time()

    def to_dict(self) -> Dict:
        return {
            "alert_type": self.alert_type,
            "src": self.src_ip,
            "pps": self.pps,
            "threshold": self.threshold,
            "timestamp": self.timestamp
        }


class BaselineDetector:
    """
    Naive sliding-window rate limiter keyed strictly on IPv6.src.
    """
    def __init__(
        self,
        rate_limit_pps: float = 6.0,
        window_seconds: float = 2.0
    ):
        self.rate_limit_pps = rate_limit_pps
        self.window_seconds = window_seconds
        # src_ip -> deque([timestamps])
        self.ip_timestamps: Dict[str, deque] = defaultdict(deque)

    def process_packet(
        self,
        src_ip: str,
        current_time: Optional[float] = None
    ) -> Optional[BaselineAlert]:
        """
        Records packet for src_ip. Returns BaselineAlert if per-IP rate exceeded.
        """
        now = current_time if current_time is not None else time.time()
        q = self.ip_timestamps[src_ip]
        q.append(now)

        # Evict timestamps outside sliding window
        while q and (now - q[0]) > self.window_seconds:
            q.popleft()

        pps = len(q) / self.window_seconds
        if pps > self.rate_limit_pps:
            return BaselineAlert(
                alert_type="BASELINE_PER_IP_RATE_EXCEEDED",
                src_ip=src_ip,
                pps=pps,
                threshold=self.rate_limit_pps,
                timestamp=now
            )
        return None

    def reset(self):
        self.ip_timestamps.clear()
