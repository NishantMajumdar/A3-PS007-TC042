#!/usr/bin/env python3
"""
pseudonym.py - PS-007 Epoch-Keyed Ephemeral Pseudonym Management Engine

Key Properties:
  - Ephemeral Pseudonyms: P = HMAC(K_epoch, tenant || session_id)[:8]
  - Configurable Epoch Length with secure in-memory overwrite of old K_epoch.
  - Multi-Tenant Isolation with segregated per-tenant stores.
  - TTL-bounded address-to-pseudonym mapping.
  - Hard session TTL (maximum unextendable session lifetime).
  - Periodic purge mechanism and strict lookup failure after expiration.
  - ZERO hardware fingerprinting (NO MAC address ingestion or storage).
"""

import os
import time
import hmac
import hashlib
from typing import Dict, List, Optional, Set, Tuple
from threading import RLock

class ExpiredPseudonymError(Exception):
    """Raised when querying an expired pseudonym or address binding."""
    pass

class AddressBinding:
    """Represents a TTL-bounded association between an IPv6 address and a pseudonym."""
    def __init__(self, addr: str, pseudonym: str, session_id: str, ttl_seconds: float, created_at: float = None):
        self.addr = addr
        self.pseudonym = pseudonym
        self.session_id = session_id
        self.created_at = created_at if created_at is not None else time.time()
        self.expires_at = self.created_at + ttl_seconds
        self.last_seen = self.created_at

    def is_expired(self, current_time: float = None) -> bool:
        now = current_time if current_time is not None else time.time()
        return now >= self.expires_at

    def touch(self, ttl_seconds: float, current_time: float = None):
        now = current_time if current_time is not None else time.time()
        self.last_seen = now
        self.expires_at = now + ttl_seconds


class SessionRecord:
    """Tracks session lifecycle, hard TTL, and address rotation chains."""
    def __init__(self, session_id: str, tenant_id: str, anchor_id: str, hard_ttl_seconds: float, created_at: float = None):
        self.session_id = session_id
        self.tenant_id = tenant_id
        self.anchor_id = anchor_id  # e.g., VLAN id or simulated link session anchor
        self.created_at = created_at if created_at is not None else time.time()
        self.hard_expires_at = self.created_at + hard_ttl_seconds
        self.last_active = self.created_at
        self.bound_addrs: Set[str] = set()
        self.addr_history: List[str] = []
        self.rotation_count = 0
        self.current_pseudonym: Optional[str] = None
        self.epoch_id = 0

    def is_hard_expired(self, current_time: float = None) -> bool:
        now = current_time if current_time is not None else time.time()
        return now >= self.hard_expires_at


class TenantStore:
    """Isolated storage boundary for a single tenant."""
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self.sessions: Dict[str, SessionRecord] = {}           # session_id -> SessionRecord
        self.addr_to_binding: Dict[str, AddressBinding] = {}   # ipv6_addr -> AddressBinding
        self.pseudonym_to_session: Dict[str, str] = {}         # pseudonym -> session_id
        self.anchor_to_session: Dict[str, str] = {}            # anchor_id -> session_id


class PseudonymManager:
    """
    Manages epoch keys, pseudonym derivation, tenant separation, and TTL life cycles.
    """
    def __init__(
        self,
        epoch_length_seconds: float = 300.0,
        default_addr_ttl: float = 120.0,
        default_hard_session_ttl: float = 3600.0
    ):
        self.epoch_length_seconds = epoch_length_seconds
        self.default_addr_ttl = default_addr_ttl
        self.default_hard_session_ttl = default_hard_session_ttl
        
        self._lock = RLock()
        self._epoch_id = 1
        self._epoch_start_time = time.time()
        
        # Secret key stored as mutable bytearray to allow cryptographically wiping old keys
        self._k_epoch: bytearray = bytearray(os.urandom(32))
        
        # Multi-tenant isolated storage
        self._tenant_stores: Dict[str, TenantStore] = {}

    def _get_or_create_tenant_store(self, tenant_id: str) -> TenantStore:
        if tenant_id not in self._tenant_stores:
            self._tenant_stores[tenant_id] = TenantStore(tenant_id)
        return self._tenant_stores[tenant_id]

    @property
    def current_epoch_id(self) -> int:
        with self._lock:
            return self._epoch_id

    def check_and_rotate_epoch_if_needed(self, current_time: float = None) -> bool:
        """Checks if current epoch duration has elapsed and performs key rotation if so."""
        now = current_time if current_time is not None else time.time()
        with self._lock:
            if now - self._epoch_start_time >= self.epoch_length_seconds:
                self.rotate_epoch(now)
                return True
            return False

    def rotate_epoch(self, current_time: float = None):
        """
        Rotates K_epoch:
          1. Overwrites/zeroes the old K_epoch in memory.
          2. Generates a fresh 32-byte pseudo-random key.
          3. Invalidates previous epoch pseudonyms across all sessions.
        """
        now = current_time if current_time is not None else time.time()
        with self._lock:
            # Cryptographic memory erasure of previous secret key
            for i in range(len(self._k_epoch)):
                self._k_epoch[i] = 0

            # Generate fresh secret key for new epoch
            self._k_epoch = bytearray(os.urandom(32))
            self._epoch_id += 1
            self._epoch_start_time = now

            # Invalidate cached pseudonym mappings across all tenants
            for store in self._tenant_stores.values():
                store.pseudonym_to_session.clear()
                for session in store.sessions.values():
                    # Recompute pseudonym for the new epoch
                    new_p = self._compute_pseudonym_raw(session.tenant_id, session.session_id)
                    session.current_pseudonym = new_p
                    session.epoch_id = self._epoch_id
                    store.pseudonym_to_session[new_p] = session.session_id

    def _compute_pseudonym_raw(self, tenant_id: str, session_id: str) -> str:
        """Computes P = HMAC(K_epoch, tenant || session_id)[:8] as hex."""
        payload = f"{tenant_id}||{session_id}".encode("utf-8")
        mac = hmac.new(bytes(self._k_epoch), payload, hashlib.sha256).hexdigest()
        # Strictly return the first 8 characters as specified
        return mac[:8].upper()

    def get_or_create_session(
        self,
        tenant_id: str,
        session_id: str,
        anchor_id: str,
        hard_ttl_seconds: Optional[float] = None,
        current_time: float = None
    ) -> Tuple[SessionRecord, str]:
        """
        Retrieves or initializes a session anchored by a link session identifier (e.g. VLAN id).
        Returns (SessionRecord, active_pseudonym).
        """
        now = current_time if current_time is not None else time.time()
        self.check_and_rotate_epoch_if_needed(now)
        ttl = hard_ttl_seconds if hard_ttl_seconds is not None else self.default_hard_session_ttl

        with self._lock:
            store = self._get_or_create_tenant_store(tenant_id)
            
            if session_id in store.sessions:
                session = store.sessions[session_id]
                if session.is_hard_expired(now):
                    # Hard TTL exceeded: remove stale session
                    self._remove_session(tenant_id, session_id)
                else:
                    session.last_active = now
                    if session.epoch_id != self._epoch_id or not session.current_pseudonym:
                        session.current_pseudonym = self._compute_pseudonym_raw(tenant_id, session_id)
                        session.epoch_id = self._epoch_id
                        store.pseudonym_to_session[session.current_pseudonym] = session_id
                    return session, session.current_pseudonym

            # Create new session
            session = SessionRecord(session_id, tenant_id, anchor_id, ttl, created_at=now)
            pseudonym = self._compute_pseudonym_raw(tenant_id, session_id)
            session.current_pseudonym = pseudonym
            session.epoch_id = self._epoch_id

            store.sessions[session_id] = session
            store.pseudonym_to_session[pseudonym] = session_id
            store.anchor_to_session[anchor_id] = session_id

            return session, pseudonym

    def get_session_by_anchor(
        self,
        tenant_id: str,
        anchor_id: str,
        current_time: float = None
    ) -> Optional[Tuple[SessionRecord, str]]:
        """Look up active session using the simulated link-session anchor (e.g., VLAN id)."""
        now = current_time if current_time is not None else time.time()
        self.check_and_rotate_epoch_if_needed(now)

        with self._lock:
            store = self._get_or_create_tenant_store(tenant_id)
            session_id = store.anchor_to_session.get(anchor_id)
            if not session_id:
                return None
            session = store.sessions.get(session_id)
            if not session or session.is_hard_expired(now):
                return None
            if session.epoch_id != self._epoch_id or not session.current_pseudonym:
                session.current_pseudonym = self._compute_pseudonym_raw(tenant_id, session_id)
                session.epoch_id = self._epoch_id
                store.pseudonym_to_session[session.current_pseudonym] = session_id
            return session, session.current_pseudonym

    def bind_address(
        self,
        tenant_id: str,
        session_id: str,
        ipv6_addr: str,
        ttl_seconds: Optional[float] = None,
        current_time: float = None
    ) -> str:
        """
        Binds a newly detected / rotated IPv6 address to the session.
        Returns the active pseudonym.
        """
        now = current_time if current_time is not None else time.time()
        self.check_and_rotate_epoch_if_needed(now)
        addr_ttl = ttl_seconds if ttl_seconds is not None else self.default_addr_ttl

        with self._lock:
            store = self._get_or_create_tenant_store(tenant_id)
            session = store.sessions.get(session_id)
            if not session:
                raise ValueError(f"Unknown session {session_id} for tenant {tenant_id}")
            if session.is_hard_expired(now):
                raise ExpiredPseudonymError(f"Session {session_id} has exceeded its hard TTL")

            if session.epoch_id != self._epoch_id or not session.current_pseudonym:
                session.current_pseudonym = self._compute_pseudonym_raw(tenant_id, session_id)
                session.epoch_id = self._epoch_id
                store.pseudonym_to_session[session.current_pseudonym] = session_id

            pseudonym = session.current_pseudonym

            # Create or update address binding
            if ipv6_addr in store.addr_to_binding:
                binding = store.addr_to_binding[ipv6_addr]
                binding.pseudonym = pseudonym
                binding.session_id = session_id
                binding.touch(addr_ttl, current_time=now)
            else:
                binding = AddressBinding(ipv6_addr, pseudonym, session_id, addr_ttl, created_at=now)
                store.addr_to_binding[ipv6_addr] = binding

            if ipv6_addr not in session.bound_addrs:
                session.bound_addrs.add(ipv6_addr)
                session.addr_history.append(ipv6_addr)
                if len(session.addr_history) > 1:
                    session.rotation_count += 1

            session.last_active = now
            return pseudonym

    def lookup_pseudonym_by_addr(
        self,
        tenant_id: str,
        ipv6_addr: str,
        current_time: float = None
    ) -> Optional[str]:
        """
        Resolves an IPv6 address to its pseudonym.
        Returns None if binding has expired, session has expired, or tenant does not match.
        """
        now = current_time if current_time is not None else time.time()
        self.check_and_rotate_epoch_if_needed(now)

        with self._lock:
            store = self._get_or_create_tenant_store(tenant_id)
            binding = store.addr_to_binding.get(ipv6_addr)
            if not binding:
                return None

            if binding.is_expired(now):
                # Expired binding: delete and fail lookup
                del store.addr_to_binding[ipv6_addr]
                return None

            session = store.sessions.get(binding.session_id)
            if not session or session.is_hard_expired(now):
                del store.addr_to_binding[ipv6_addr]
                return None

            # Verify epoch validity
            if session.epoch_id != self._epoch_id:
                # Pseudonym must be recalculated for current epoch
                new_p = self._compute_pseudonym_raw(tenant_id, session.session_id)
                session.current_pseudonym = new_p
                session.epoch_id = self._epoch_id
                store.pseudonym_to_session[new_p] = session.session_id
                binding.pseudonym = new_p

            return binding.pseudonym

    def lookup_session_by_pseudonym(
        self,
        tenant_id: str,
        pseudonym: str,
        current_time: float = None
    ) -> Optional[SessionRecord]:
        """Looks up a session by its current pseudonym within a tenant's scope."""
        now = current_time if current_time is not None else time.time()
        self.check_and_rotate_epoch_if_needed(now)

        with self._lock:
            store = self._get_or_create_tenant_store(tenant_id)
            session_id = store.pseudonym_to_session.get(pseudonym)
            if not session_id:
                return None
            session = store.sessions.get(session_id)
            if not session or session.is_hard_expired(now):
                return None
            return session

    def _remove_session(self, tenant_id: str, session_id: str):
        store = self._tenant_stores.get(tenant_id)
        if not store or session_id not in store.sessions:
            return
        session = store.sessions.pop(session_id)
        if session.current_pseudonym in store.pseudonym_to_session:
            del store.pseudonym_to_session[session.current_pseudonym]
        if session.anchor_id in store.anchor_to_session:
            del store.anchor_to_session[session.anchor_id]
        # Clean associated address bindings
        for addr in session.bound_addrs:
            if addr in store.addr_to_binding:
                del store.addr_to_binding[addr]

    def purge(self, current_time: float = None) -> Dict[str, int]:
        """
        Purges expired bindings, expired sessions, and outdated keys across all tenants.
        Returns purge statistics.
        """
        now = current_time if current_time is not None else time.time()
        epoch_rotated = self.check_and_rotate_epoch_if_needed(now)

        purged_addrs = 0
        purged_sessions = 0

        with self._lock:
            for store in self._tenant_stores.values():
                # 1. Purge expired address bindings
                expired_addrs = [addr for addr, b in store.addr_to_binding.items() if b.is_expired(now)]
                for addr in expired_addrs:
                    del store.addr_to_binding[addr]
                    purged_addrs += 1

                # 2. Purge hard-expired sessions
                expired_session_ids = [sid for sid, s in store.sessions.items() if s.is_hard_expired(now)]
                for sid in expired_session_ids:
                    self._remove_session(store.tenant_id, sid)
                    purged_sessions += 1

        return {
            "purged_addrs": purged_addrs,
            "purged_sessions": purged_sessions,
            "epoch_rotated": 1 if epoch_rotated else 0
        }

    def wipe_all_keys_and_stores(self):
        """Emergency purge / zeroing of all keys and states in memory."""
        with self._lock:
            for i in range(len(self._k_epoch)):
                self._k_epoch[i] = 0
            self._k_epoch = bytearray(32)
            self._tenant_stores.clear()
