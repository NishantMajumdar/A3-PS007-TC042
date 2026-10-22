#!/usr/bin/env python3
"""
attribution.py - PS-007 Mirrored Traffic Attribution & DAD Binding Engine

Core Responsibilities:
  1. Sniff mirrored switch traffic (tagged with VLAN ID = 4100 + in_port).
  2. Map vlan_id -> simulated link session -> ephemeral pseudonym (via PseudonymManager).
  3. Inspect valid DAD NS packets (src ::, target = tentative own address).
  4. Enforce a bounded allowance of address bindings per rotation window.
  5. Strictly DROP all hardware MAC addresses at ingress (no Ether.src read or stored).
"""

import time
import ipaddress
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple
from threading import RLock

from pseudonym import PseudonymManager

class AttributionEvent:
    """Encapsulates the attribution result of a processed network frame."""
    def __init__(
        self,
        event_type: str,            # "BIND_DAD", "DATA", "REJECT_EXCEEDED", "UNBOUND"
        pseudonym: Optional[str],
        session_id: Optional[str],
        vlan_id: int,
        ipv6_src: str,
        ipv6_dst: str,
        target_addr: Optional[str] = None,
        details: str = "",
        timestamp: float = None
    ):
        self.event_type = event_type
        self.pseudonym = pseudonym
        self.session_id = session_id
        self.vlan_id = vlan_id
        self.ipv6_src = ipv6_src
        self.ipv6_dst = ipv6_dst
        self.target_addr = target_addr
        self.details = details
        self.timestamp = timestamp if timestamp is not None else time.time()

    def to_dict(self) -> Dict:
        return {
            "type": self.event_type,
            "pseudonym": self.pseudonym,
            "session_id": self.session_id,
            "vlan_id": self.vlan_id,
            "src": self.ipv6_src,
            "dst": self.ipv6_dst,
            "target": self.target_addr,
            "details": self.details,
            "timestamp": self.timestamp
        }


class AttributionEngine:
    """
    Processes mirrored traffic, manages DAD address bindings, and resolves pseudonyms.
    """
    def __init__(
        self,
        pseudonym_manager: PseudonymManager,
        expected_prefix: str = "fd00:abcd::/64",
        max_bindings_per_rotation: int = 3,
        rotation_window_seconds: float = 60.0,
        default_tenant: str = "default"
    ):
        self.pm = pseudonym_manager
        self.expected_network = ipaddress.IPv6Network(expected_prefix)
        self.max_bindings_per_rotation = max_bindings_per_rotation
        self.rotation_window_seconds = rotation_window_seconds
        self.default_tenant = default_tenant

        self._lock = RLock()
        
        # Track recent DAD bindings per session for bounded allowance:
        # (tenant, session_id) -> deque([timestamp1, timestamp2, ...])
        self._session_dad_timestamps: Dict[Tuple[str, str], deque] = defaultdict(deque)

        # Mapping of vlan_id -> static session_id seed to ensure deterministic link anchor
        self._vlan_to_session_id: Dict[int, str] = {}

    def _get_session_id_for_vlan(self, vlan_id: int) -> str:
        """Derives a stable session identifier from the link anchor (vlan_id)."""
        if vlan_id not in self._vlan_to_session_id:
            port = vlan_id - 4100 if vlan_id >= 4100 else vlan_id
            self._vlan_to_session_id[vlan_id] = f"SES-PORT{port:02d}"
        return self._vlan_to_session_id[vlan_id]

    def _is_valid_dad_ns(self, ipv6_src: str, ipv6_dst: str, hop_limit: int, target_ip: str) -> Tuple[bool, str]:
        """
        Validates RFC 4862 Duplicate Address Detection Neighbor Solicitation constraints:
          1. Source MUST be the unspecified address (::)
          2. Hop limit MUST be 255
          3. Target address MUST be a valid IPv6 unicast address
          4. Target address SHOULD belong to expected subnet or link-local
        """
        if ipv6_src != "::":
            return False, f"DAD NS source must be ::, got {ipv6_src}"

        if hop_limit != 255:
            return False, f"DAD NS hop limit must be 255, got {hop_limit}"

        try:
            target_obj = ipaddress.IPv6Address(target_ip)
        except Exception:
            return False, f"Invalid target IPv6 address: {target_ip}"

        if target_obj.is_multicast:
            return False, "DAD target address cannot be multicast"

        if target_obj.is_unspecified or target_obj.is_loopback:
            return False, "DAD target cannot be loopback or unspecified"

        # Check if it matches the expected prefix or is link-local (fe80::)
        if not (target_obj in self.expected_network or target_obj.is_link_local):
            return False, f"Target {target_ip} outside expected network {self.expected_network}"

        return True, "Valid DAD NS"

    def handle_dad_ns(
        self,
        vlan_id: int,
        target_ip: str,
        ipv6_src: str = "::",
        ipv6_dst: str = "ff02::1",
        hop_limit: int = 255,
        tenant_id: Optional[str] = None,
        current_time: Optional[float] = None
    ) -> AttributionEvent:
        """
        Evaluates a DAD NS packet and binds the tentative address to the session
        if bounded allowance constraints are satisfied.
        """
        now = current_time if current_time is not None else time.time()
        tenant = tenant_id or self.default_tenant

        # 1. Validate RFC 4862 DAD syntax
        valid, reason = self._is_valid_dad_ns(ipv6_src, ipv6_dst, hop_limit, target_ip)
        session_id = self._get_session_id_for_vlan(vlan_id)
        anchor_id = f"vlan-{vlan_id}"

        if not valid:
            return AttributionEvent(
                event_type="REJECT_INVALID_DAD",
                pseudonym=None,
                session_id=session_id,
                vlan_id=vlan_id,
                ipv6_src=ipv6_src,
                ipv6_dst=ipv6_dst,
                target_addr=target_ip,
                details=reason,
                timestamp=now
            )

        with self._lock:
            # 2. Get or create the session for this VLAN anchor
            session, pseudonym = self.pm.get_or_create_session(
                tenant_id=tenant,
                session_id=session_id,
                anchor_id=anchor_id,
                current_time=now
            )

            # 3. Check bounded allowance per rotation window
            key = (tenant, session_id)
            timestamps = self._session_dad_timestamps[key]
            # Evict timestamps older than rotation_window_seconds
            while timestamps and (now - timestamps[0]) > self.rotation_window_seconds:
                timestamps.popleft()

            if len(timestamps) >= self.max_bindings_per_rotation:
                # Exceeded rate allowance for this rotation period
                return AttributionEvent(
                    event_type="REJECT_EXCEEDED",
                    pseudonym=pseudonym,
                    session_id=session_id,
                    vlan_id=vlan_id,
                    ipv6_src=ipv6_src,
                    ipv6_dst=ipv6_dst,
                    target_addr=target_ip,
                    details=f"Exceeded max DAD bindings ({self.max_bindings_per_rotation}/{self.rotation_window_seconds}s)",
                    timestamp=now
                )

            # 4. Allowance accepted: Record timestamp and bind address
            timestamps.append(now)
            active_p = self.pm.bind_address(
                tenant_id=tenant,
                session_id=session_id,
                ipv6_addr=target_ip,
                current_time=now
            )

            return AttributionEvent(
                event_type="BIND_DAD",
                pseudonym=active_p,
                session_id=session_id,
                vlan_id=vlan_id,
                ipv6_src=ipv6_src,
                ipv6_dst=ipv6_dst,
                target_addr=target_ip,
                details=f"Bound tentative address {target_ip} to {active_p} (allowance {len(timestamps)}/{self.max_bindings_per_rotation})",
                timestamp=now
            )

    def process_raw_scapy_packet(
        self,
        packet,
        tenant_id: Optional[str] = None,
        current_time: Optional[float] = None
    ) -> Optional[AttributionEvent]:
        """
        Ingests a mirrored packet from Scapy.
        CRITICAL CONSTRAINT: Strips and DROPS all Ethernet / MAC headers immediately.
        """
        now = current_time if current_time is not None else time.time()
        tenant = tenant_id or self.default_tenant

        # 1. Extract VLAN tag (Anchor). Drop packet if not mirrored with VLAN tag.
        from scapy.all import Dot1Q, IPv6, ICMPv6ND_NS
        
        vlan_id = None
        if Dot1Q in packet:
            vlan_id = packet[Dot1Q].vlan
        else:
            # Untagged packet on monitor interface
            return None

        # 2. Extract IPv6 Layer. Absolutely DO NOT access or store packet[Ether].src / dst.
        if IPv6 not in packet:
            return None

        ip_pkt = packet[IPv6]
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        hlim = ip_pkt.hlim

        # 3. Check for Duplicate Address Detection (DAD) Neighbor Solicitation
        if ICMPv6ND_NS in packet and src_ip == "::":
            ns_pkt = packet[ICMPv6ND_NS]
            target_ip = ns_pkt.tgt
            return self.handle_dad_ns(
                vlan_id=vlan_id,
                target_ip=target_ip,
                ipv6_src=src_ip,
                ipv6_dst=dst_ip,
                hop_limit=hlim,
                tenant_id=tenant,
                current_time=now
            )

        # 4. Standard Traffic Attribution: Resolve source IP to pseudonym
        session_id = self._get_session_id_for_vlan(vlan_id)
        pseudonym = self.pm.lookup_pseudonym_by_addr(tenant, src_ip, current_time=now)

        if pseudonym:
            return AttributionEvent(
                event_type="DATA",
                pseudonym=pseudonym,
                session_id=session_id,
                vlan_id=vlan_id,
                ipv6_src=src_ip,
                ipv6_dst=dst_ip,
                details="Attributed active traffic to existing pseudonym",
                timestamp=now
            )
        else:
            return AttributionEvent(
                event_type="UNBOUND",
                pseudonym=None,
                session_id=session_id,
                vlan_id=vlan_id,
                ipv6_src=src_ip,
                ipv6_dst=dst_ip,
                details=f"Traffic from {src_ip} without prior DAD binding",
                timestamp=now
            )
