"""
K-Valkyrie Node Feature Embedder
Extracts and normalizes multi-modal behavioral features for Process, File, Socket,
and MemFD entities into fixed 16-dimensional embedding vectors.
"""

from __future__ import annotations
import math
import zlib
from typing import Dict, List, Optional, Any


def calculate_shannon_entropy(data: str) -> float:
    """Calculates normalized Shannon entropy [0.0 - 1.0] of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    freq: Dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    # Normalize by maximum possible entropy for ASCII (8 bits)
    return min(entropy / 8.0, 1.0)


def hash_string_feature(val: str, salt: int = 0) -> float:
    """Deterministic CRC32-based float projection into [0.0, 1.0]."""
    if not val:
        return 0.0
    h = zlib.crc32(f"{salt}_{val}".encode("utf-8")) & 0xFFFFFFFF
    return float(h % 10000) / 10000.0


class NodeEmbedder:
    """
    Produces standardized 16-dimensional feature vectors:
    [0..3] : Node Type One-Hot (Process, File, MemFD, Socket)
    [4]    : Is Root / Elevated (UID == 0)
    [5]    : Is Container / Isolated (cgroup_id != 0)
    [6]    : Is Flagged / Quarantined
    [7]    : Normalized String Entropy (path / name randomness)
    [8]    : Hash Feature 1 (comm / extension identifier)
    [9]    : Hash Feature 2 (path / argument fingerprint)
    [10]   : Temporal Activity Frequency
    [11]   : Privilege Ratio (UID / 65534)
    [12]   : Permission / Mode bits normalized
    [13..15]: Reserved domain features / zero padding
    """

    DIMENSION = 16

    @staticmethod
    def embed_process(
        pid: int,
        ppid: int,
        uid: int,
        gid: int,
        cgroup_id: int,
        comm: str,
        is_quarantined: bool = False,
        activity_freq: float = 0.5,
    ) -> List[float]:
        vec = [0.0] * NodeEmbedder.DIMENSION
        vec[0] = 1.0  # Node type: Process
        vec[4] = 1.0 if uid == 0 else 0.0
        vec[5] = 1.0 if cgroup_id != 0 else 0.0
        vec[6] = 1.0 if is_quarantined else 0.0
        vec[7] = calculate_shannon_entropy(comm)
        vec[8] = hash_string_feature(comm, salt=1)
        vec[9] = hash_string_feature(str(ppid), salt=2)
        vec[10] = min(max(activity_freq, 0.0), 1.0)
        vec[11] = min(float(uid) / 65534.0, 1.0)
        vec[12] = 1.0 if ppid <= 1 else 0.0  # Daemon or orphan process indicator
        return vec

    @staticmethod
    def embed_file(
        path: str,
        inode: int,
        in_container: bool = False,
        is_quarantined: bool = False,
        is_sensitive: bool = False,
    ) -> List[float]:
        vec = [0.0] * NodeEmbedder.DIMENSION
        vec[1] = 1.0  # Node type: File
        vec[4] = 1.0 if is_sensitive else 0.0
        vec[5] = 1.0 if in_container else 0.0
        vec[6] = 1.0 if is_quarantined else 0.0
        vec[7] = calculate_shannon_entropy(path)
        vec[8] = hash_string_feature(path, salt=10)
        vec[9] = float(inode % 10000) / 10000.0
        vec[10] = 1.0 if "/tmp" in path or "/dev/shm" in path else 0.0
        vec[11] = 1.0 if path.endswith((".sh", ".so", ".bin", ".elf", "")) else 0.0
        vec[12] = 1.0 if is_sensitive else 0.0
        return vec

    @staticmethod
    def embed_memfd(
        name: str,
        creator_pid: int,
        in_container: bool = False,
        fd_flags: int = 0,
    ) -> List[float]:
        vec = [0.0] * NodeEmbedder.DIMENSION
        vec[2] = 1.0  # Node type: MemFD
        vec[4] = 1.0  # MemFD execution inherently elevated risk
        vec[5] = 1.0 if in_container else 0.0
        vec[6] = 0.0
        vec[7] = calculate_shannon_entropy(name)
        vec[8] = hash_string_feature(name, salt=20)
        vec[9] = hash_string_feature(str(creator_pid), salt=21)
        vec[10] = 1.0  # High anomaly prior
        vec[11] = float(fd_flags & 0xFF) / 255.0
        vec[12] = 1.0  # Fileless anonymous primitive
        return vec

    @staticmethod
    def embed_socket(
        remote_ip: str,
        port: int,
        protocol: str = "tcp",
        in_container: bool = False,
        is_known_c2: bool = False,
    ) -> List[float]:
        vec = [0.0] * NodeEmbedder.DIMENSION
        vec[3] = 1.0  # Node type: Socket
        vec[4] = 1.0 if is_known_c2 else 0.0
        vec[5] = 1.0 if in_container else 0.0
        vec[6] = 1.0 if is_known_c2 else 0.0
        vec[7] = calculate_shannon_entropy(remote_ip)
        vec[8] = hash_string_feature(remote_ip, salt=30)
        vec[9] = min(float(port) / 65535.0, 1.0)
        vec[10] = 1.0 if protocol.lower() == "tcp" else 0.5
        vec[11] = 1.0 if port in (4444, 1337, 6667, 8888, 9999) else 0.0
        vec[12] = 1.0 if is_known_c2 else 0.0
        return vec
