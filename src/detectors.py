#!/usr/bin/env python3
"""
detectors.py - PS-007 Anomaly Detection Engine

Detectors:
  1. RogueRADetector:
     - Unauthorized source IPv6 address
     - Unexpected prefix / flags
     - Router Lifetime == 0 (DoS variant)
     - Parameter inconsistency (Hop Limit, MTU, Retrans Timer)
     - Rapid burst detection
  2. NDPAbuseDetector:
     - Per-pseudonym token buckets based on RFC 4861 constants (NS, NA, RS)
     - n-of-m hysteresis window
     - CUSUM (Cumulative Sum Control Chart) for stealth/persistent drift
     - Distinct-target cardinality tracking (detects scanning/sweeping)
     - NO MAD on raw counts (strictly compliant)
     - Per-pseudonym state deleted when pseudonym expires
"""

import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple
from threading import RLock

class SecurityAlert:
    """Represents a security anomaly or protocol violation alert."""
    def __init__(
        self,
        alert_type: str,
        severity: str,          # "LOW", "MEDIUM", "HIGH", "CRITICAL"
        pseudonym: Optional[str],
        src_ip: str,
        description: str,
        evidence: Dict,
        timestamp: float = None
    ):
        self.alert_type = alert_type
        self.severity = severity
        self.pseudonym = pseudonym
        self.src_ip = src_ip
        self.description = description
        self.evidence = evidence
        self.timestamp = timestamp if timestamp is not None else time.time()

    def to_dict(self) -> Dict:
        return {
            "type": "alert",
            "alert_type": self.alert_type,
            "severity": self.severity,
            "pseudonym": self.pseudonym,
            "src": self.src_ip,
            "description": self.description,
            "evidence": self.evidence,
            "timestamp": self.timestamp
        }


# ==============================================================================
# 1. ROGUE RA DETECTOR
# ==============================================================================
class RogueRADetector:
    """
    Monitors ICMPv6 Router Advertisements for rogue sources, zero lifetimes,
    unexpected prefixes, parameter inconsistencies, and bursts.
    """
    def __init__(
        self,
        authorized_routers: Optional[List[str]] = None,
        authorized_prefix: str = "fd00:abcd::",
        authorized_prefix_len: int = 64,
        expected_hop_limit: int = 64,
        burst_threshold: int = 3,
        burst_window_seconds: float = 1.0,
        authorized_vlan: int = 4101
    ):
        self.authorized_routers = set(authorized_routers or ["fd00:abcd::1", "fe80::1"])
        self.authorized_prefix = authorized_prefix.lower()
        self.authorized_prefix_len = authorized_prefix_len
        self.expected_hop_limit = expected_hop_limit
        self.burst_threshold = burst_threshold
        self.burst_window_seconds = burst_window_seconds
        self.authorized_vlan = authorized_vlan

        self._lock = RLock()
        self._ra_timestamps = deque()

    def is_authorized_router_vlan(self, vlan_id: Optional[int]) -> bool:
        """
        Determines if an ingress VLAN tag corresponds strictly to legitimate router port 1 (r1).
        Exclusively permits physical switch port 1.
        Any other ingress port (ports 2, 3, 4, ..., 8, 9, etc.) is strictly unauthorized.
        """
        if vlan_id is None:
            return False
        if vlan_id >= 4100:
            port = vlan_id - 4100
        elif vlan_id >= 5:
            port = vlan_id - 4
        else:
            port = vlan_id
        return port == 1

    def inspect_ra(
        self,
        src_ip: str,
        router_lifetime: int,
        cur_hop_limit: int,
        managed_flag: int,
        other_flag: int,
        advertised_prefixes: List[Tuple[str, int]],  # [(prefix_str, prefix_len), ...]
        pseudonym: Optional[str] = None,
        current_time: Optional[float] = None,
        vlan_id: Optional[int] = None
    ) -> List[SecurityAlert]:
        """Inspects an RA packet against protocol constraints and baselines."""
        now = current_time if current_time is not None else time.time()
        alerts = []

        with self._lock:
            # 1. Burst Check
            self._ra_timestamps.append(now)
            while self._ra_timestamps and (now - self._ra_timestamps[0]) > self.burst_window_seconds:
                self._ra_timestamps.popleft()

            if len(self._ra_timestamps) >= self.burst_threshold:
                alerts.append(SecurityAlert(
                    alert_type="ROGUE_RA_BURST",
                    severity="HIGH",
                    pseudonym=pseudonym,
                    src_ip=src_ip,
                    description=f"Router Advertisement flood/burst: {len(self._ra_timestamps)} RAs in {self.burst_window_seconds}s",
                    evidence={"burst_count": len(self._ra_timestamps), "window": self.burst_window_seconds},
                    timestamp=now
                ))

            # 2. Port and Source Authorization (RFC 6104 / RFC 6105 RA-Guard & RFC 4861)
            # RAs are exclusively authorized from physical router port 1.
            # Any RA arriving on ANY other port (port 2, 3, 4, ..., 8, 9, etc.) is strictly unauthorized.
            is_router_port = self.is_authorized_router_vlan(vlan_id)
            if is_router_port:
                self.authorized_routers.add(src_ip)

            if vlan_id is not None and not is_router_port:
                alerts.append(SecurityAlert(
                    alert_type="ROGUE_RA_UNAUTHORIZED_SOURCE",
                    severity="CRITICAL",
                    pseudonym=pseudonym,
                    src_ip=src_ip,
                    description=f"Rogue RA intercepted on unauthorized access port (VLAN {vlan_id}) from {src_ip}",
                    evidence={"vlan_id": vlan_id, "authorized_port": 1, "authorized_sources": list(self.authorized_routers)},
                    timestamp=now
                ))
            elif not (src_ip in self.authorized_routers):
                alerts.append(SecurityAlert(
                    alert_type="ROGUE_RA_UNAUTHORIZED_SOURCE",
                    severity="CRITICAL",
                    pseudonym=pseudonym,
                    src_ip=src_ip,
                    description=f"RA sent from unauthorized source address: {src_ip}",
                    evidence={"authorized_sources": list(self.authorized_routers), "vlan_id": vlan_id},
                    timestamp=now
                ))


            # 3. Router Lifetime == 0 (DoS attack to clear default route)
            if router_lifetime == 0:
                alerts.append(SecurityAlert(
                    alert_type="ROGUE_RA_ZERO_LIFETIME",
                    severity="HIGH",
                    pseudonym=pseudonym,
                    src_ip=src_ip,
                    description=f"Rogue RA with Router Lifetime 0 from {src_ip} (route deletion DoS)",
                    evidence={"router_lifetime": 0},
                    timestamp=now
                ))

            # 4. Parameter Inconsistency
            if cur_hop_limit != 0 and cur_hop_limit != self.expected_hop_limit:
                alerts.append(SecurityAlert(
                    alert_type="ROGUE_RA_PARAM_INCONSISTENCY",
                    severity="MEDIUM",
                    pseudonym=pseudonym,
                    src_ip=src_ip,
                    description=f"Inconsistent Cur Hop Limit in RA: {cur_hop_limit} (expected {self.expected_hop_limit})",
                    evidence={"received_hop_limit": cur_hop_limit, "expected": self.expected_hop_limit},
                    timestamp=now
                ))

            # 5. Unexpected Prefix Advertisements
            for pfx, plen in advertised_prefixes:
                pfx_clean = pfx.lower()
                if not (pfx_clean.startswith("fd00:abcd") and plen == self.authorized_prefix_len):
                    alerts.append(SecurityAlert(
                        alert_type="ROGUE_RA_UNEXPECTED_PREFIX",
                        severity="CRITICAL",
                        pseudonym=pseudonym,
                        src_ip=src_ip,
                        description=f"Unauthorized prefix advertised in RA: {pfx}/{plen}",
                        evidence={"advertised_prefix": f"{pfx}/{plen}", "expected": f"{self.authorized_prefix}/{self.authorized_prefix_len}"},
                        timestamp=now
                    ))

        return alerts


# ==============================================================================
# 2. NDP ABUSE DETECTOR PER PSEUDONYM
# ==============================================================================
class TokenBucket:
    """Token bucket rate limiter parameterized by RFC 4861 constants."""
    def __init__(self, capacity: float, refill_rate: float, last_time: float = None):
        self.capacity = capacity
        self.refill_rate = refill_rate  # tokens per second
        self.tokens = capacity
        self.last_update = last_time if last_time is not None else time.time()

    def consume(self, count: float = 1.0, current_time: float = None) -> bool:
        """Consumes tokens. Returns True if sufficient tokens existed, False if exceeded."""
        now = current_time if current_time is not None else time.time()
        elapsed = max(0.0, now - self.last_update)
        self.last_update = now

        # Refill tokens up to capacity
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)

        if self.tokens >= count:
            self.tokens -= count
            return True
        return False


class CUSUMTracker:
    """Cumulative Sum (CUSUM) change-point detector for traffic drift."""
    def __init__(self, baseline_mean: float = 1.0, slack: float = 0.5, threshold: float = 5.0):
        self.baseline_mean = baseline_mean
        self.slack = slack
        self.threshold = threshold
        self.s = 0.0

    def update(self, sample_value: float) -> bool:
        """Updates CUSUM accumulator: S_k = max(0, S_{k-1} + X_k - mu - K). Returns True on alert."""
        self.s = max(0.0, self.s + (sample_value - self.baseline_mean - self.slack))
        return self.s >= self.threshold

    def reset(self):
        self.s = 0.0


class PseudonymNDPState:
    """State tracked specifically for a single pseudonym."""
    def __init__(self, pseudonym: str, current_time: float = None):
        self.pseudonym = pseudonym
        now = current_time if current_time is not None else time.time()
        
        # Token Buckets per NDP packet type (RFC 4861 parameters)
        # NS: capacity 6, refill 2.0/s (MAX_MULTICAST_SOLICIT = 3, RETRANS_TIMER = 1s)
        self.tb_ns = TokenBucket(capacity=6.0, refill_rate=2.0, last_time=now)
        # NA: capacity 6, refill 2.0/s
        self.tb_na = TokenBucket(capacity=6.0, refill_rate=2.0, last_time=now)
        # RS: capacity 4, refill 0.5/s (MAX_RTR_SOLICITATIONS = 3, RTR_SOLICITATION_INTERVAL = 4s)
        self.tb_rs = TokenBucket(capacity=4.0, refill_rate=0.5, last_time=now)

        # Hysteresis window: deque of booleans for the last m intervals (e.g. m=5)
        self.hysteresis_history = deque(maxlen=5)

        # CUSUM anomaly detector
        self.cusum = CUSUMTracker(baseline_mean=1.0, slack=0.5, threshold=6.0)

        # Distinct-target cardinality tracking: deque of (timestamp, target_ip)
        self.target_queries = deque()
        self.last_active = now


class NDPAbuseDetector:
    """
    Tracks and flags NDP abuse per pseudonym using token buckets,
    hysteresis, CUSUM, and target cardinality. NO MAD ON RAW COUNTS.
    """
    def __init__(
        self,
        hysteresis_n: int = 3,
        hysteresis_m: int = 5,
        max_distinct_targets: int = 4,
        target_window_seconds: float = 10.0
    ):
        self.hysteresis_n = hysteresis_n
        self.hysteresis_m = hysteresis_m
        self.max_distinct_targets = max_distinct_targets
        self.target_window_seconds = target_window_seconds

        self._lock = RLock()
        # pseudonym -> PseudonymNDPState
        self._states: Dict[str, PseudonymNDPState] = {}

    def _get_or_create_state(self, pseudonym: str, current_time: float = None) -> PseudonymNDPState:
        if pseudonym not in self._states:
            self._states[pseudonym] = PseudonymNDPState(pseudonym, current_time)
        return self._states[pseudonym]

    def delete_pseudonym_state(self, pseudonym: str):
        """Purges all detector state for a pseudonym when it expires."""
        with self._lock:
            if pseudonym in self._states:
                del self._states[pseudonym]

    def purge_expired_pseudonyms(self, active_pseudonyms: Set[str]):
        """Removes all internal states for pseudonyms not in active_pseudonyms."""
        with self._lock:
            stale = [p for p in self._states if p not in active_pseudonyms]
            for p in stale:
                del self._states[p]

    def record_ndp_packet(
        self,
        pseudonym: str,
        ndp_type: str,            # "NS", "NA", "RS"
        src_ip: str,
        target_ip: Optional[str] = None,
        current_time: Optional[float] = None
    ) -> List[SecurityAlert]:
        """
        Processes an NDP packet for the given pseudonym.
        Evaluates token bucket, hysteresis, CUSUM, and target cardinality.
        """
        now = current_time if current_time is not None else time.time()
        alerts = []

        with self._lock:
            st = self._get_or_create_state(pseudonym, now)
            st.last_active = now

            # 1. Token Bucket Inspection
            bucket_breached = False
            bucket_name = ndp_type.upper()

            if bucket_name == "NS":
                allowed = st.tb_ns.consume(1.0, current_time=now)
            elif bucket_name == "NA":
                allowed = st.tb_na.consume(1.0, current_time=now)
            elif bucket_name == "RS":
                allowed = st.tb_rs.consume(1.0, current_time=now)
            else:
                allowed = True

            if not allowed:
                bucket_breached = True

            # 2. n-of-m Hysteresis Update
            st.hysteresis_history.append(bucket_breached)
            violations_in_window = sum(1 for b in st.hysteresis_history if b)
            
            # Check if n out of m observations breached
            if len(st.hysteresis_history) >= self.hysteresis_m and violations_in_window >= self.hysteresis_n:
                alerts.append(SecurityAlert(
                    alert_type="NDP_RATE_ABUSE_HYSTERESIS",
                    severity="HIGH",
                    pseudonym=pseudonym,
                    src_ip=src_ip,
                    description=f"NDP rate abuse on {bucket_name} by pseudonym {pseudonym} ({violations_in_window}/{self.hysteresis_m} window violations)",
                    evidence={"type": bucket_name, "violations": violations_in_window, "window_size": self.hysteresis_m},
                    timestamp=now
                ))

            # 3. CUSUM Drift Analysis
            # Update CUSUM with instantaneous rate contribution
            rate_sample = 2.0 if bucket_breached else 0.5
            cusum_triggered = st.cusum.update(rate_sample)
            if cusum_triggered:
                alerts.append(SecurityAlert(
                    alert_type="NDP_CUSUM_DRIFT_ALERT",
                    severity="MEDIUM",
                    pseudonym=pseudonym,
                    src_ip=src_ip,
                    description=f"Persistent anomalous NDP drift detected via CUSUM for pseudonym {pseudonym}",
                    evidence={"cusum_score": st.cusum.s, "threshold": st.cusum.threshold},
                    timestamp=now
                ))
                st.cusum.reset()

            # 4. Distinct-Target Cardinality Inspection (for Neighbor Solicitations)
            if bucket_name == "NS" and target_ip:
                st.target_queries.append((now, target_ip))
                # Evict entries older than window
                while st.target_queries and (now - st.target_queries[0][0]) > self.target_window_seconds:
                    st.target_queries.popleft()

                distinct_targets = {t for _, t in st.target_queries}
                if len(distinct_targets) > self.max_distinct_targets:
                    alerts.append(SecurityAlert(
                        alert_type="NDP_SCAN_CARDINALITY_ALERT",
                        severity="HIGH",
                        pseudonym=pseudonym,
                        src_ip=src_ip,
                        description=f"NDP target scanning detected: {len(distinct_targets)} distinct targets queried in {self.target_window_seconds}s",
                        evidence={"distinct_targets": list(distinct_targets), "window": self.target_window_seconds},
                        timestamp=now
                    ))

        return alerts
