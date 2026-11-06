"""
K-Valkyrie BPF Map Controller
Writes blocked PIDs and inodes into kernel BPF maps for real-time enforcement.
Uses ctypes/libbpf to update the ``quarantined_pids`` BPF hash map.
On non-Linux hosts, operates on an in-memory dictionary simulation.
"""

from __future__ import annotations

import ctypes
import logging
import os
import platform
import struct
import threading
from enum import IntEnum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

IS_LINUX = platform.system() == "Linux"


class QuarantineAction(IntEnum):
    """Enforcement actions written as BPF map values."""
    ALLOW = 0
    LOG_ONLY = 1
    DENY = 2
    SIGKILL = 3
    SIGSTOP = 4


# ---------------------------------------------------------------------------
# Linux libbpf map operations via ctypes
# ---------------------------------------------------------------------------
class _LibbpfMapOps:
    """
    Thin ctypes wrapper around libbpf/bpf syscall helpers for hash map
    update / delete / lookup operations.

    Uses bpf_map_update_elem, bpf_map_delete_elem, and bpf_map_lookup_elem
    from libbpf, or falls back to the raw bpf() syscall via ctypes.
    """

    # bpf() syscall number on x86_64
    _SYS_BPF = 321
    _BPF_MAP_LOOKUP_ELEM = 1
    _BPF_MAP_UPDATE_ELEM = 2
    _BPF_MAP_DELETE_ELEM = 3
    _BPF_MAP_GET_NEXT_KEY = 4

    # BPF_ANY flag
    _BPF_ANY = 0

    def __init__(self) -> None:
        self._lib: Optional[ctypes.CDLL] = None
        self._use_libbpf = False
        self._libc: Optional[ctypes.CDLL] = None

    def _load(self) -> None:
        """Load libbpf or libc for bpf syscall access."""
        # Try libbpf first
        for path in ("libbpf.so.1", "libbpf.so"):
            try:
                self._lib = ctypes.CDLL(path)
                self._use_libbpf = True
                logger.info("MapController using libbpf from %s", path)
                return
            except OSError:
                continue

        # Fallback to raw syscall via libc
        try:
            self._libc = ctypes.CDLL("libc.so.6")
            logger.info("MapController using raw bpf() syscall via libc")
        except OSError as exc:
            raise RuntimeError(
                "Cannot load libbpf or libc for BPF map operations"
            ) from exc

    def _ensure_loaded(self) -> None:
        if self._lib is None and self._libc is None:
            self._load()

    def update_elem(
        self, map_fd: int, key_bytes: bytes, value_bytes: bytes, flags: int = 0
    ) -> int:
        """
        Update an element in a BPF map.

        Returns 0 on success, negative errno on failure.
        """
        self._ensure_loaded()
        if self._use_libbpf and self._lib is not None:
            self._lib.bpf_map_update_elem.restype = ctypes.c_int
            self._lib.bpf_map_update_elem.argtypes = [
                ctypes.c_int,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_uint64,
            ]
            key_buf = ctypes.create_string_buffer(key_bytes)
            val_buf = ctypes.create_string_buffer(value_bytes)
            return self._lib.bpf_map_update_elem(
                map_fd,
                ctypes.byref(key_buf),
                ctypes.byref(val_buf),
                flags,
            )
        # Raw syscall path
        return self._raw_bpf_update(map_fd, key_bytes, value_bytes, flags)

    def delete_elem(self, map_fd: int, key_bytes: bytes) -> int:
        """
        Delete an element from a BPF map.

        Returns 0 on success, negative errno on failure.
        """
        self._ensure_loaded()
        if self._use_libbpf and self._lib is not None:
            self._lib.bpf_map_delete_elem.restype = ctypes.c_int
            self._lib.bpf_map_delete_elem.argtypes = [
                ctypes.c_int,
                ctypes.c_void_p,
            ]
            key_buf = ctypes.create_string_buffer(key_bytes)
            return self._lib.bpf_map_delete_elem(map_fd, ctypes.byref(key_buf))
        return self._raw_bpf_delete(map_fd, key_bytes)

    def lookup_elem(
        self, map_fd: int, key_bytes: bytes, value_size: int
    ) -> Optional[bytes]:
        """
        Look up an element in a BPF map.

        Returns value bytes on success, None on failure.
        """
        self._ensure_loaded()
        if self._use_libbpf and self._lib is not None:
            self._lib.bpf_map_lookup_elem.restype = ctypes.c_int
            self._lib.bpf_map_lookup_elem.argtypes = [
                ctypes.c_int,
                ctypes.c_void_p,
                ctypes.c_void_p,
            ]
            key_buf = ctypes.create_string_buffer(key_bytes)
            val_buf = ctypes.create_string_buffer(value_size)
            ret = self._lib.bpf_map_lookup_elem(
                map_fd, ctypes.byref(key_buf), ctypes.byref(val_buf)
            )
            if ret == 0:
                return val_buf.raw[:value_size]
            return None
        return self._raw_bpf_lookup(map_fd, key_bytes, value_size)

    def get_next_key(
        self, map_fd: int, key_bytes: Optional[bytes], key_size: int
    ) -> Optional[bytes]:
        """
        Iterate BPF map keys. Pass None for the first key.

        Returns next key bytes, or None if iteration is complete.
        """
        self._ensure_loaded()
        if self._use_libbpf and self._lib is not None:
            self._lib.bpf_map_get_next_key.restype = ctypes.c_int
            self._lib.bpf_map_get_next_key.argtypes = [
                ctypes.c_int,
                ctypes.c_void_p,
                ctypes.c_void_p,
            ]
            next_key_buf = ctypes.create_string_buffer(key_size)
            if key_bytes is not None:
                key_buf = ctypes.create_string_buffer(key_bytes)
                key_ptr = ctypes.byref(key_buf)
            else:
                key_ptr = None
            ret = self._lib.bpf_map_get_next_key(
                map_fd, key_ptr, ctypes.byref(next_key_buf)
            )
            if ret == 0:
                return next_key_buf.raw[:key_size]
            return None
        return None

    # -- Raw bpf() syscall helpers -----------------------------------------
    def _raw_bpf_update(
        self, map_fd: int, key: bytes, value: bytes, flags: int
    ) -> int:
        """bpf(BPF_MAP_UPDATE_ELEM, ...) via raw syscall."""
        if self._libc is None:
            return -1
        # Build bpf_attr union (simplified for update_elem)
        # struct { __u32 map_fd; __aligned_u64 key; __aligned_u64 value; __u64 flags; }
        attr = struct.pack(
            "=I4xQQQ",
            map_fd,
            ctypes.addressof(ctypes.create_string_buffer(key)),
            ctypes.addressof(ctypes.create_string_buffer(value)),
            flags,
        )
        self._libc.syscall.restype = ctypes.c_long
        return self._libc.syscall(self._SYS_BPF, self._BPF_MAP_UPDATE_ELEM, attr, len(attr))

    def _raw_bpf_delete(self, map_fd: int, key: bytes) -> int:
        if self._libc is None:
            return -1
        attr = struct.pack(
            "=I4xQ",
            map_fd,
            ctypes.addressof(ctypes.create_string_buffer(key)),
        )
        self._libc.syscall.restype = ctypes.c_long
        return self._libc.syscall(self._SYS_BPF, self._BPF_MAP_DELETE_ELEM, attr, len(attr))

    def _raw_bpf_lookup(
        self, map_fd: int, key: bytes, value_size: int
    ) -> Optional[bytes]:
        if self._libc is None:
            return None
        val_buf = ctypes.create_string_buffer(value_size)
        attr = struct.pack(
            "=I4xQQ",
            map_fd,
            ctypes.addressof(ctypes.create_string_buffer(key)),
            ctypes.addressof(val_buf),
        )
        self._libc.syscall.restype = ctypes.c_long
        ret = self._libc.syscall(self._SYS_BPF, self._BPF_MAP_LOOKUP_ELEM, attr, len(attr))
        if ret == 0:
            return val_buf.raw[:value_size]
        return None


# ---------------------------------------------------------------------------
# In-memory simulation for non-Linux platforms
# ---------------------------------------------------------------------------
class _SimulatedMapOps:
    """In-memory dictionary simulating BPF hash map operations."""

    def __init__(self) -> None:
        self._store: Dict[bytes, bytes] = {}

    def update_elem(
        self, map_fd: int, key_bytes: bytes, value_bytes: bytes, flags: int = 0
    ) -> int:
        self._store[key_bytes] = value_bytes
        return 0

    def delete_elem(self, map_fd: int, key_bytes: bytes) -> int:
        if key_bytes in self._store:
            del self._store[key_bytes]
            return 0
        return -2  # -ENOENT

    def lookup_elem(
        self, map_fd: int, key_bytes: bytes, value_size: int
    ) -> Optional[bytes]:
        val = self._store.get(key_bytes)
        if val is not None:
            return val.ljust(value_size, b"\x00")[:value_size]
        return None

    def get_next_key(
        self, map_fd: int, key_bytes: Optional[bytes], key_size: int
    ) -> Optional[bytes]:
        keys = sorted(self._store.keys())
        if not keys:
            return None
        if key_bytes is None:
            return keys[0]
        try:
            idx = keys.index(key_bytes)
            if idx + 1 < len(keys):
                return keys[idx + 1]
        except ValueError:
            if keys:
                return keys[0]
        return None

    def get_all(self) -> Dict[bytes, bytes]:
        return dict(self._store)


# ---------------------------------------------------------------------------
# Public API – MapController
# ---------------------------------------------------------------------------
class MapController:
    """
    Controls the ``quarantined_pids`` BPF hash map for real-time kernel
    enforcement of PID quarantine decisions.

    Map schema:
        Key:   u32 (PID)
        Value: u8  (QuarantineAction)

    On non-Linux platforms, uses an in-memory simulation.

    Usage::

        ctrl = MapController(map_fd=5)
        ctrl.add_quarantine(pid=4192, action=QuarantineAction.DENY)
        ctrl.remove_quarantine(pid=4192)
        entries = ctrl.list_quarantined()
    """

    # Key and value sizes for the quarantined_pids map
    _KEY_SIZE = 4    # u32
    _VALUE_SIZE = 1  # u8

    def __init__(
        self,
        map_fd: int = -1,
        force_simulation: bool = False,
    ) -> None:
        """
        Args:
            map_fd: BPF map file descriptor (Linux only, ignored in simulation).
            force_simulation: Force in-memory simulation even on Linux.
        """
        self._map_fd = map_fd
        self._simulation_mode = not IS_LINUX or force_simulation
        self._lock = threading.Lock()

        if self._simulation_mode:
            self._ops: _SimulatedMapOps | _LibbpfMapOps = _SimulatedMapOps()
            logger.info("MapController running in SIMULATION mode")
        else:
            self._ops = _LibbpfMapOps()
            logger.info("MapController running in LIVE BPF mode (fd=%d)", map_fd)

    @property
    def simulation_mode(self) -> bool:
        """Whether the controller is in simulation mode."""
        return self._simulation_mode

    @staticmethod
    def _pid_to_key(pid: int) -> bytes:
        """Encode PID as little-endian u32 bytes."""
        return struct.pack("<I", pid)

    @staticmethod
    def _action_to_value(action: int | QuarantineAction) -> bytes:
        """Encode action as a single u8 byte."""
        return struct.pack("<B", int(action))

    @staticmethod
    def _key_to_pid(key_bytes: bytes) -> int:
        """Decode u32 PID from key bytes."""
        return struct.unpack("<I", key_bytes[:4])[0]

    @staticmethod
    def _value_to_action(value_bytes: bytes) -> QuarantineAction:
        """Decode u8 action from value bytes."""
        raw = struct.unpack("<B", value_bytes[:1])[0]
        try:
            return QuarantineAction(raw)
        except ValueError:
            return QuarantineAction.ALLOW

    def add_quarantine(
        self,
        pid: int,
        action: int | QuarantineAction = QuarantineAction.DENY,
    ) -> bool:
        """
        Add a PID to the quarantine map with the specified enforcement action.

        Args:
            pid: Process ID to quarantine.
            action: Enforcement action (ALLOW, LOG_ONLY, DENY, SIGKILL, SIGSTOP).

        Returns:
            True on success, False on failure.
        """
        key = self._pid_to_key(pid)
        value = self._action_to_value(action)
        with self._lock:
            ret = self._ops.update_elem(self._map_fd, key, value)
        if ret == 0:
            logger.info(
                "Quarantined PID %d with action %s",
                pid,
                QuarantineAction(int(action)).name,
            )
            return True
        logger.warning("Failed to quarantine PID %d (ret=%d)", pid, ret)
        return False

    def remove_quarantine(self, pid: int) -> bool:
        """
        Remove a PID from the quarantine map.

        Args:
            pid: Process ID to un-quarantine.

        Returns:
            True on success, False if PID was not found.
        """
        key = self._pid_to_key(pid)
        with self._lock:
            ret = self._ops.delete_elem(self._map_fd, key)
        if ret == 0:
            logger.info("Removed quarantine for PID %d", pid)
            return True
        logger.debug("PID %d not found in quarantine map", pid)
        return False

    def is_quarantined(self, pid: int) -> Optional[QuarantineAction]:
        """
        Check if a PID is currently quarantined.

        Args:
            pid: Process ID to check.

        Returns:
            The quarantine action if found, None otherwise.
        """
        key = self._pid_to_key(pid)
        with self._lock:
            result = self._ops.lookup_elem(self._map_fd, key, self._VALUE_SIZE)
        if result is not None:
            return self._value_to_action(result)
        return None

    def list_quarantined(self) -> Dict[int, QuarantineAction]:
        """
        List all currently quarantined PIDs and their actions.

        Returns:
            Dictionary mapping PID -> QuarantineAction.
        """
        entries: Dict[int, QuarantineAction] = {}

        # Simulation fast path
        if self._simulation_mode and isinstance(self._ops, _SimulatedMapOps):
            with self._lock:
                for k, v in self._ops.get_all().items():
                    pid = self._key_to_pid(k)
                    action = self._value_to_action(v)
                    entries[pid] = action
            return entries

        # Linux: iterate using get_next_key
        with self._lock:
            key_bytes: Optional[bytes] = None
            seen: Set[bytes] = set()
            while True:
                next_key = self._ops.get_next_key(
                    self._map_fd, key_bytes, self._KEY_SIZE
                )
                if next_key is None or next_key in seen:
                    break
                seen.add(next_key)
                val = self._ops.lookup_elem(
                    self._map_fd, next_key, self._VALUE_SIZE
                )
                if val is not None:
                    pid = self._key_to_pid(next_key)
                    action = self._value_to_action(val)
                    entries[pid] = action
                key_bytes = next_key
        return entries

    def bulk_update(
        self,
        updates: Dict[int, int | QuarantineAction],
    ) -> Tuple[int, int]:
        """
        Batch update multiple PIDs in the quarantine map.

        Args:
            updates: Dictionary mapping PID -> action.

        Returns:
            Tuple of (success_count, failure_count).
        """
        success = 0
        failure = 0
        for pid, action in updates.items():
            if self.add_quarantine(pid, action):
                success += 1
            else:
                failure += 1
        logger.info(
            "Bulk update: %d succeeded, %d failed out of %d",
            success,
            failure,
            len(updates),
        )
        return success, failure

    def bulk_remove(self, pids: List[int]) -> Tuple[int, int]:
        """
        Batch remove multiple PIDs from the quarantine map.

        Args:
            pids: List of PIDs to remove.

        Returns:
            Tuple of (success_count, failure_count).
        """
        success = 0
        failure = 0
        for pid in pids:
            if self.remove_quarantine(pid):
                success += 1
            else:
                failure += 1
        return success, failure

    def clear_all(self) -> int:
        """
        Remove all entries from the quarantine map.

        Returns:
            Number of entries removed.
        """
        entries = self.list_quarantined()
        count = 0
        for pid in entries:
            if self.remove_quarantine(pid):
                count += 1
        logger.info("Cleared %d quarantine entries", count)
        return count
