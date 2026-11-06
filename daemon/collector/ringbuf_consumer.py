"""
K-Valkyrie eBPF Ring Buffer Consumer
High-throughput ring buffer consumer that reads SyscallEventRaw structs from
the eBPF ring buffer file descriptor. On non-Linux platforms, provides a
simulation mode generating realistic mock events for development/testing.
"""

from __future__ import annotations

import ctypes
import logging
import os
import platform
import random
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

IS_LINUX = platform.system() == "Linux"

# ---------------------------------------------------------------------------
# SyscallEventRaw – must match headers/common_events.h layout exactly
# ---------------------------------------------------------------------------
class SyscallEventRaw(ctypes.Structure):
    """
    Binary struct matching the eBPF common_events.h layout.

    Fields:
        timestamp_ns  u64    Monotonic kernel timestamp
        cgroup_id     u64    Container cgroup v2 ID
        inode         u64    Target file inode
        pid           u32    Task PID
        ppid          u32    Parent PID
        uid           u32    Effective UID
        gid           u32    Effective GID
        syscall_id    u32    Hooked syscall or LSM ID
        target_pid    u32    ptrace / kill target PID
        fd_flags      u32    File descriptor flags
        action_taken  u32    0=allow, 1=log, 2=deny, 3=kill
        comm          char[16]   Process command name
        filename      char[128]  Target file path / name
    """
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("cgroup_id", ctypes.c_uint64),
        ("inode", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("syscall_id", ctypes.c_uint32),
        ("target_pid", ctypes.c_uint32),
        ("fd_flags", ctypes.c_uint32),
        ("action_taken", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("filename", ctypes.c_char * 128),
    ]


STRUCT_SIZE = ctypes.sizeof(SyscallEventRaw)

# Syscall constants (matching graph_builder.py)
VALKYRIE_SYS_EXECVE = 59
VALKYRIE_SYS_PTRACE = 101
VALKYRIE_SYS_MEMFD_CREATE = 319
VALKYRIE_SYS_EXECVEAT = 322
VALKYRIE_LSM_BPRM_CHECK = 1001
VALKYRIE_LSM_FILE_OPEN = 1002

# Callback type: receives a parsed SyscallEventRaw
EventCallback = Callable[[SyscallEventRaw], None]


def parse_raw_bytes(raw: bytes) -> SyscallEventRaw:
    """Parse raw ring-buffer bytes into a SyscallEventRaw ctypes struct."""
    if len(raw) < STRUCT_SIZE:
        padded = raw + b"\x00" * (STRUCT_SIZE - len(raw))
    else:
        padded = raw[:STRUCT_SIZE]
    event = SyscallEventRaw()
    ctypes.memmove(ctypes.byref(event), padded, STRUCT_SIZE)
    return event


# ---------------------------------------------------------------------------
# Linux libbpf ring-buffer consumer (ctypes bindings)
# ---------------------------------------------------------------------------
class _LibbpfRingBuf:
    """
    Thin ctypes wrapper around libbpf's ring_buffer__new / ring_buffer__poll.
    Requires libbpf.so.1 installed on the host.
    """

    def __init__(self) -> None:
        self._lib: Optional[ctypes.CDLL] = None
        self._rb: Optional[ctypes.c_void_p] = None
        self._callbacks: List[EventCallback] = []
        self._c_callback: Optional[ctypes.CFUNCTYPE] = None
        self._loaded = False

    def _load_libbpf(self) -> ctypes.CDLL:
        """Attempt to load libbpf shared library."""
        search_paths = [
            "libbpf.so.1",
            "libbpf.so",
            "/usr/lib/x86_64-linux-gnu/libbpf.so.1",
            "/usr/lib64/libbpf.so.1",
        ]
        last_err: Optional[Exception] = None
        for path in search_paths:
            try:
                lib = ctypes.CDLL(path)
                logger.info("Loaded libbpf from %s", path)
                return lib
            except OSError as exc:
                last_err = exc
                continue
        raise RuntimeError(
            f"Cannot load libbpf shared library. Last error: {last_err}"
        )

    # ring_buffer callback signature: int (*)(void *ctx, void *data, size_t data_sz)
    _RING_BUFFER_SAMPLE_FN = ctypes.CFUNCTYPE(
        ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t
    )

    def _handle_event(
        self, ctx: ctypes.c_void_p, data: ctypes.c_void_p, data_sz: int
    ) -> int:
        """C-callback invoked by libbpf for each ring buffer sample."""
        try:
            raw = ctypes.string_at(data, min(data_sz, STRUCT_SIZE))
            event = parse_raw_bytes(raw)
            for cb in self._callbacks:
                cb(event)
        except Exception:
            logger.exception("Error processing ring buffer event")
        return 0

    def open(self, map_fd: int) -> None:
        """
        Open the BPF ring buffer on the given map file descriptor.

        Args:
            map_fd: File descriptor of the BPF_MAP_TYPE_RINGBUF map.
        """
        self._lib = self._load_libbpf()

        self._c_callback = self._RING_BUFFER_SAMPLE_FN(self._handle_event)

        # ring_buffer *ring_buffer__new(int map_fd, ring_buffer_sample_fn fn,
        #                               void *ctx, const struct ring_buffer_opts *opts);
        self._lib.ring_buffer__new.restype = ctypes.c_void_p
        self._lib.ring_buffer__new.argtypes = [
            ctypes.c_int,
            self._RING_BUFFER_SAMPLE_FN,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        self._rb = self._lib.ring_buffer__new(
            map_fd, self._c_callback, None, None
        )
        if not self._rb:
            raise RuntimeError("ring_buffer__new returned NULL – check map fd")
        self._loaded = True
        logger.info("BPF ring buffer opened on fd=%d", map_fd)

    def poll(self, timeout_ms: int = 100) -> int:
        """
        Poll the ring buffer for new events.

        Args:
            timeout_ms: Max milliseconds to block waiting for events.

        Returns:
            Number of events consumed (negative on error).
        """
        if not self._loaded or self._rb is None or self._lib is None:
            raise RuntimeError("Ring buffer not opened. Call open() first.")
        self._lib.ring_buffer__poll.restype = ctypes.c_int
        self._lib.ring_buffer__poll.argtypes = [ctypes.c_void_p, ctypes.c_int]
        return self._lib.ring_buffer__poll(self._rb, timeout_ms)

    def free(self) -> None:
        """Free the ring buffer resources."""
        if self._lib is not None and self._rb is not None:
            try:
                self._lib.ring_buffer__free.restype = None
                self._lib.ring_buffer__free.argtypes = [ctypes.c_void_p]
                self._lib.ring_buffer__free(self._rb)
            except Exception:
                logger.exception("Error freeing ring buffer")
            finally:
                self._rb = None
                self._loaded = False

    def register_callback(self, cb: EventCallback) -> None:
        """Register a callback to be invoked for each parsed event."""
        self._callbacks.append(cb)


# ---------------------------------------------------------------------------
# Mock / Simulation ring-buffer consumer for non-Linux platforms
# ---------------------------------------------------------------------------
class _SimulatedRingBuf:
    """
    Generates synthetic SyscallEventRaw events that mimic realistic kernel
    telemetry patterns for development and testing on non-Linux hosts.
    """

    _BENIGN_COMMS = [
        b"bash", b"ls", b"cat", b"grep", b"awk", b"systemd", b"sshd",
        b"nginx", b"python3", b"node", b"java", b"containerd",
    ]
    _BENIGN_FILES = [
        b"/usr/bin/ls", b"/usr/bin/cat", b"/usr/bin/grep",
        b"/tmp/data.txt", b"/var/log/syslog", b"/etc/hostname",
        b"/home/user/.bashrc", b"/lib/x86_64-linux-gnu/libc.so.6",
    ]
    _ATTACK_COMMS = [b"python3", b"perl", b"curl", b"wget"]
    _ATTACK_FILES = [
        b"/proc/self/fd/3", b"anon_elf_loader",
        b"/dev/shm/payload", b"/etc/shadow",
    ]

    def __init__(self) -> None:
        self._callbacks: List[EventCallback] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._base_pid = 1000
        self._event_count = 0
        self._attack_probability = 0.05

    def register_callback(self, cb: EventCallback) -> None:
        """Register a callback for simulated events."""
        self._callbacks.append(cb)

    def _make_event(
        self,
        *,
        syscall_id: int,
        pid: int,
        ppid: int,
        uid: int = 1000,
        gid: int = 1000,
        cgroup_id: int = 0,
        comm: bytes = b"bash",
        filename: bytes = b"/usr/bin/bash",
        target_pid: int = 0,
        action_taken: int = 0,
    ) -> SyscallEventRaw:
        """Construct a SyscallEventRaw from keyword arguments."""
        event = SyscallEventRaw()
        event.timestamp_ns = int(time.time_ns())
        event.cgroup_id = cgroup_id
        event.inode = random.randint(100000, 999999)
        event.pid = pid
        event.ppid = ppid
        event.uid = uid
        event.gid = gid
        event.syscall_id = syscall_id
        event.target_pid = target_pid
        event.fd_flags = 0
        event.action_taken = action_taken
        event.comm = comm[:16].ljust(16, b"\x00")
        event.filename = filename[:128].ljust(128, b"\x00")
        return event

    def _generate_benign_event(self) -> SyscallEventRaw:
        """Generate a single realistic benign event."""
        syscall = random.choice([
            VALKYRIE_SYS_EXECVE,
            VALKYRIE_LSM_FILE_OPEN,
            VALKYRIE_LSM_BPRM_CHECK,
        ])
        pid = self._base_pid + random.randint(0, 5000)
        ppid = max(1, pid - random.randint(1, 100))
        return self._make_event(
            syscall_id=syscall,
            pid=pid,
            ppid=ppid,
            comm=random.choice(self._BENIGN_COMMS),
            filename=random.choice(self._BENIGN_FILES),
        )

    def _generate_attack_event(self) -> SyscallEventRaw:
        """Generate a single attack-simulating event."""
        attack_type = random.choice(["memfd", "ptrace", "exec_fileless"])
        pid = self._base_pid + random.randint(3000, 9000)
        ppid = max(1, pid - random.randint(1, 50))
        if attack_type == "memfd":
            return self._make_event(
                syscall_id=VALKYRIE_SYS_MEMFD_CREATE,
                pid=pid,
                ppid=ppid,
                uid=0,
                gid=0,
                cgroup_id=random.randint(100, 200),
                comm=random.choice(self._ATTACK_COMMS),
                filename=b"anon_elf_loader",
            )
        elif attack_type == "ptrace":
            return self._make_event(
                syscall_id=VALKYRIE_SYS_PTRACE,
                pid=pid,
                ppid=ppid,
                uid=0,
                gid=0,
                target_pid=random.randint(1, 3000),
                comm=b"gdb",
                filename=b"",
            )
        else:
            return self._make_event(
                syscall_id=VALKYRIE_SYS_EXECVE,
                pid=pid,
                ppid=ppid,
                uid=0,
                gid=0,
                cgroup_id=random.randint(100, 200),
                comm=random.choice(self._ATTACK_COMMS),
                filename=random.choice(self._ATTACK_FILES),
            )

    def poll(self, timeout_ms: int = 100) -> int:
        """
        Generate and dispatch simulated events.

        Args:
            timeout_ms: Simulated poll wait (used as sleep in ms).

        Returns:
            Number of events generated in this poll cycle.
        """
        time.sleep(timeout_ms / 1000.0)
        batch_size = random.randint(1, 8)
        count = 0
        for _ in range(batch_size):
            if random.random() < self._attack_probability:
                event = self._generate_attack_event()
            else:
                event = self._generate_benign_event()
            self._event_count += 1
            for cb in self._callbacks:
                try:
                    cb(event)
                except Exception:
                    logger.exception("Error in simulation callback")
            count += 1
        return count

    def start_continuous(
        self,
        poll_interval_ms: int = 100,
        max_events: int = 0,
    ) -> None:
        """
        Start continuous event generation in a background thread.

        Args:
            poll_interval_ms: Interval between poll cycles.
            max_events: Stop after this many events (0 = unlimited).
        """
        if self._running:
            return
        self._running = True

        def _loop() -> None:
            total = 0
            while self._running:
                n = self.poll(poll_interval_ms)
                total += n
                if 0 < max_events <= total:
                    break
            self._running = False

        self._thread = threading.Thread(target=_loop, daemon=True, name="sim-ringbuf")
        self._thread.start()

    def stop(self) -> None:
        """Stop continuous event generation."""
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None


# ---------------------------------------------------------------------------
# Public API – RingBufConsumer
# ---------------------------------------------------------------------------
class RingBufConsumer:
    """
    High-level ring buffer consumer API.

    On Linux, wraps libbpf's ring_buffer__new/poll. On other platforms,
    automatically falls back to simulation mode.

    Usage::

        consumer = RingBufConsumer()
        consumer.register_callback(my_handler)
        # Linux:
        consumer.open(map_fd=42)
        consumer.poll_loop(timeout_ms=100)
        # Non-Linux:
        consumer.start_simulation(poll_interval_ms=50, max_events=1000)
    """

    def __init__(self, force_simulation: bool = False) -> None:
        """
        Args:
            force_simulation: If True, use simulation mode even on Linux.
        """
        self._force_sim = force_simulation
        self._simulation_mode = not IS_LINUX or force_simulation
        self._callbacks: List[EventCallback] = []
        self._running = False
        self._poll_thread: Optional[threading.Thread] = None
        self._events_consumed: int = 0
        self._lock = threading.Lock()

        if self._simulation_mode:
            self._backend: _SimulatedRingBuf | _LibbpfRingBuf = _SimulatedRingBuf()
            logger.info(
                "RingBufConsumer initialized in SIMULATION mode (platform=%s)",
                platform.system(),
            )
        else:
            self._backend = _LibbpfRingBuf()
            logger.info("RingBufConsumer initialized in LIVE eBPF mode")

    @property
    def simulation_mode(self) -> bool:
        """Whether the consumer is running in simulation mode."""
        return self._simulation_mode

    @property
    def events_consumed(self) -> int:
        """Total events consumed since initialization."""
        return self._events_consumed

    def register_callback(self, callback: EventCallback) -> None:
        """
        Register a callback to be invoked for each event.

        The callback receives a parsed ``SyscallEventRaw`` struct.
        """
        self._callbacks.append(callback)
        self._backend.register_callback(self._wrap_callback(callback))

    def _wrap_callback(self, callback: EventCallback) -> EventCallback:
        """Wrap user callback with internal bookkeeping."""
        def _wrapped(event: SyscallEventRaw) -> None:
            with self._lock:
                self._events_consumed += 1
            callback(event)
        return _wrapped

    # -- Linux live mode ---------------------------------------------------
    def open(self, map_fd: int) -> None:
        """
        Open the BPF ring buffer (Linux only).

        Args:
            map_fd: File descriptor for the BPF_MAP_TYPE_RINGBUF map.

        Raises:
            RuntimeError: If not on Linux or libbpf is unavailable.
        """
        if self._simulation_mode:
            raise RuntimeError(
                "Cannot open BPF ring buffer in simulation mode. "
                "Use start_simulation() instead."
            )
        assert isinstance(self._backend, _LibbpfRingBuf)
        self._backend.open(map_fd)

    def poll(self, timeout_ms: int = 100) -> int:
        """
        Poll for events once.

        Args:
            timeout_ms: Maximum time to block in milliseconds.

        Returns:
            Number of events consumed (negative indicates error on Linux).
        """
        return self._backend.poll(timeout_ms)

    def poll_loop(
        self,
        timeout_ms: int = 100,
        max_events: int = 0,
        blocking: bool = True,
    ) -> None:
        """
        Continuously poll for events.

        Args:
            timeout_ms: Poll timeout per cycle.
            max_events: Stop after N events (0 = unlimited).
            blocking: If False, run in a background thread.
        """
        self._running = True

        def _loop() -> None:
            total = 0
            while self._running:
                n = self.poll(timeout_ms)
                if n > 0:
                    total += n
                if 0 < max_events <= total:
                    break
            self._running = False

        if blocking:
            _loop()
        else:
            self._poll_thread = threading.Thread(
                target=_loop, daemon=True, name="ringbuf-poll"
            )
            self._poll_thread.start()

    # -- Simulation mode ---------------------------------------------------
    def start_simulation(
        self,
        poll_interval_ms: int = 100,
        max_events: int = 0,
    ) -> None:
        """
        Start simulation event generation.

        Args:
            poll_interval_ms: Interval between generation cycles.
            max_events: Stop after N events (0 = unlimited).
        """
        if not self._simulation_mode:
            raise RuntimeError("Not in simulation mode. Use poll_loop() instead.")
        assert isinstance(self._backend, _SimulatedRingBuf)
        self._backend.start_continuous(poll_interval_ms, max_events)

    def stop(self) -> None:
        """Stop polling or simulation."""
        self._running = False
        if isinstance(self._backend, _SimulatedRingBuf):
            self._backend.stop()
        if isinstance(self._backend, _LibbpfRingBuf):
            self._backend.free()
        if self._poll_thread is not None:
            self._poll_thread.join(timeout=5.0)
            self._poll_thread = None


# Compatibility alias
RingBufferConsumer = RingBufConsumer
