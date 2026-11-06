"""
K-Valkyrie Container Enricher
Maps cgroup_id and PID namespace to container metadata by reading procfs
and querying Docker / CRI-O / containerd sockets for pod-level information.
Provides graceful fallback when not running in a containerized environment.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import re
import socket
import time
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

logger = logging.getLogger(__name__)

IS_LINUX = platform.system() == "Linux"

# Default socket paths for container runtimes
DOCKER_SOCKET = "/var/run/docker.sock"
CONTAINERD_SOCKET = "/run/containerd/containerd.sock"
CRIO_SOCKET = "/var/run/crio/crio.sock"


@dataclass(frozen=True)
class ContainerInfo:
    """Immutable container metadata enrichment record."""
    container_id: str = ""
    container_name: str = ""
    image: str = ""
    k8s_namespace: str = ""
    k8s_pod_name: str = ""
    runtime: str = ""
    cgroup_path: str = ""
    pid_namespace: str = ""

    def to_dict(self) -> Dict[str, str]:
        """Serialize to a plain dictionary."""
        return {
            "container_id": self.container_id,
            "container_name": self.container_name,
            "image": self.image,
            "k8s_namespace": self.k8s_namespace,
            "k8s_pod_name": self.k8s_pod_name,
            "runtime": self.runtime,
            "cgroup_path": self.cgroup_path,
            "pid_namespace": self.pid_namespace,
        }


# Regex patterns for extracting container IDs from cgroup paths
_DOCKER_CG_RE = re.compile(
    r"/docker/([a-f0-9]{64})"
    r"|/docker-([a-f0-9]{64})\.scope"
    r"|/system\.slice/docker-([a-f0-9]{64})\.scope"
)
_CONTAINERD_CG_RE = re.compile(
    r"/cri-containerd-([a-f0-9]{64})\.scope"
    r"|/containerd/([a-f0-9]{64})"
)
_CRIO_CG_RE = re.compile(
    r"/crio-([a-f0-9]{64})\.scope"
    r"|/crio/([a-f0-9]{64})"
)
_K8S_POD_RE = re.compile(
    r"/kubepods[^/]*/(?:pod([a-f0-9-]+))"
    r"|/kubepods\.slice/kubepods-[^/]+\.slice/kubepods-[^/]+-pod([a-f0-9_]+)\.slice"
)

# Empty sentinel for non-container processes
_EMPTY_INFO = ContainerInfo()


def _read_proc_file(pid: int, filename: str) -> Optional[str]:
    """Safely read a procfs file for a given PID."""
    path = Path(f"/proc/{pid}/{filename}")
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (FileNotFoundError, PermissionError, OSError):
        return None


def _extract_container_id_from_cgroup(cgroup_content: str) -> Tuple[str, str, str]:
    """
    Parse /proc/<pid>/cgroup content to extract container ID and runtime.

    Returns:
        (container_id, runtime_name, full_cgroup_path)
    """
    for line in cgroup_content.splitlines():
        # cgroup v2 format: "0::/system.slice/docker-<id>.scope"
        # cgroup v1 format: "12:cpuset:/docker/<id>"
        parts = line.strip().split(":", maxsplit=2)
        if len(parts) < 3:
            continue
        cg_path = parts[2]

        # Docker
        m = _DOCKER_CG_RE.search(cg_path)
        if m:
            cid = next((g for g in m.groups() if g), "")
            return cid, "docker", cg_path

        # containerd / CRI
        m = _CONTAINERD_CG_RE.search(cg_path)
        if m:
            cid = next((g for g in m.groups() if g), "")
            return cid, "containerd", cg_path

        # CRI-O
        m = _CRIO_CG_RE.search(cg_path)
        if m:
            cid = next((g for g in m.groups() if g), "")
            return cid, "crio", cg_path

    return "", "", ""


def _extract_k8s_pod_uid(cgroup_content: str) -> str:
    """Extract Kubernetes pod UID from cgroup path."""
    for line in cgroup_content.splitlines():
        parts = line.strip().split(":", maxsplit=2)
        if len(parts) < 3:
            continue
        m = _K8S_POD_RE.search(parts[2])
        if m:
            pod_uid = next((g for g in m.groups() if g), "")
            return pod_uid.replace("_", "-")
    return ""


def _extract_pid_namespace(pid: int) -> str:
    """Read the PID namespace inode for a process."""
    ns_path = f"/proc/{pid}/ns/pid"
    try:
        target = os.readlink(ns_path)
        return target  # e.g., "pid:[4026531836]"
    except (FileNotFoundError, PermissionError, OSError):
        return ""


def _extract_nspid(pid: int) -> int:
    """
    Read NSpid from /proc/<pid>/status to find the PID inside the container
    namespace.
    """
    content = _read_proc_file(pid, "status")
    if content is None:
        return 0
    for line in content.splitlines():
        if line.startswith("NSpid:"):
            pids = line.split()[1:]
            if len(pids) >= 2:
                try:
                    return int(pids[-1])
                except ValueError:
                    pass
    return 0


class _DockerClient:
    """
    Minimal Docker Engine API client using Unix domain sockets.
    Avoids the heavy docker-py dependency.
    """

    def __init__(self, socket_path: str = DOCKER_SOCKET) -> None:
        self._socket_path = socket_path
        self._available: Optional[bool] = None

    @property
    def available(self) -> bool:
        """Check if the Docker socket exists and is accessible."""
        if self._available is None:
            self._available = os.path.exists(self._socket_path)
        return self._available

    def _request(self, method: str, path: str) -> Optional[Dict[str, Any]]:
        """Send an HTTP request over the Docker unix socket."""
        if not self.available:
            return None
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            sock.connect(self._socket_path)

            request_line = f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            sock.sendall(request_line.encode("utf-8"))

            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            sock.close()

            # Split headers and body
            decoded = response.decode("utf-8", errors="replace")
            header_end = decoded.find("\r\n\r\n")
            if header_end < 0:
                return None
            body = decoded[header_end + 4:]

            # Handle chunked transfer encoding
            headers_text = decoded[:header_end].lower()
            if "transfer-encoding: chunked" in headers_text:
                body = self._decode_chunked(body)

            return json.loads(body)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            logger.debug("Docker socket request failed: %s", exc)
            return None

    @staticmethod
    def _decode_chunked(body: str) -> str:
        """Decode HTTP chunked transfer encoding."""
        result_parts: List[str] = []
        remaining = body
        while remaining:
            line_end = remaining.find("\r\n")
            if line_end < 0:
                break
            size_str = remaining[:line_end].strip()
            if not size_str:
                remaining = remaining[line_end + 2:]
                continue
            try:
                chunk_size = int(size_str, 16)
            except ValueError:
                break
            if chunk_size == 0:
                break
            chunk_start = line_end + 2
            chunk_end = chunk_start + chunk_size
            result_parts.append(remaining[chunk_start:chunk_end])
            remaining = remaining[chunk_end + 2:]
        return "".join(result_parts)

    def inspect_container(self, container_id: str) -> Optional[Dict[str, Any]]:
        """
        GET /containers/<id>/json from Docker daemon.
        """
        short_id = container_id[:12]
        return self._request("GET", f"/containers/{short_id}/json")


class _CrictlClient:
    """
    Minimal wrapper around crictl CLI for CRI-O / containerd inspection
    when Docker socket is unavailable.
    """

    def __init__(self) -> None:
        self._available: Optional[bool] = None

    @property
    def available(self) -> bool:
        """Check if crictl binary is available."""
        if self._available is None:
            self._available = os.path.isfile("/usr/bin/crictl") or os.path.isfile(
                "/usr/local/bin/crictl"
            )
        return self._available

    def inspect_container(self, container_id: str) -> Optional[Dict[str, Any]]:
        """Run crictl inspect and parse JSON output."""
        if not self.available:
            return None
        import subprocess

        try:
            result = subprocess.run(
                ["crictl", "inspect", container_id[:12]],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout:
                return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass
        return None


class ContainerEnricher:
    """
    Maps cgroup_id and PID namespace information to container metadata.

    Reads /proc/<pid>/cgroup, /proc/<pid>/status, and queries Docker/CRI
    sockets for container and Kubernetes pod details.

    On non-Linux platforms or when no container runtime is detected, returns
    empty ContainerInfo with graceful fallback.

    Usage::

        enricher = ContainerEnricher()
        info = enricher.enrich(pid=12345, cgroup_id=42)
        print(info.container_id, info.k8s_pod_name)
    """

    def __init__(
        self,
        docker_socket: str = DOCKER_SOCKET,
        cache_ttl_seconds: float = 30.0,
    ) -> None:
        """
        Args:
            docker_socket: Path to Docker UNIX socket.
            cache_ttl_seconds: TTL for cached container lookups.
        """
        self._docker = _DockerClient(docker_socket)
        self._crictl = _CrictlClient()
        self._cache: Dict[str, Tuple[float, ContainerInfo]] = {}
        self._cache_ttl = cache_ttl_seconds

    def _get_cached(self, key: str) -> Optional[ContainerInfo]:
        """Return cached result if not expired."""
        entry = self._cache.get(key)
        if entry is None:
            return None
        ts, info = entry
        if (time.monotonic() - ts) > self._cache_ttl:
            del self._cache[key]
            return None
        return info

    def _set_cached(self, key: str, info: ContainerInfo) -> None:
        """Store an enrichment result in cache."""
        self._cache[key] = (time.monotonic(), info)

    def enrich(self, pid: int, cgroup_id: int = 0) -> ContainerInfo:
        """
        Perform container enrichment for a given PID and cgroup ID.

        Args:
            pid: Process ID to enrich.
            cgroup_id: cgroup v2 ID (from eBPF event). Used as cache hint.

        Returns:
            ContainerInfo with available fields populated.
        """
        cache_key = f"{pid}:{cgroup_id}"
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        if not IS_LINUX:
            info = self._simulate_enrichment(pid, cgroup_id)
            self._set_cached(cache_key, info)
            return info

        # Step 1: Read cgroup file
        cgroup_content = _read_proc_file(pid, "cgroup")
        if cgroup_content is None:
            self._set_cached(cache_key, _EMPTY_INFO)
            return _EMPTY_INFO

        # Step 2: Extract container ID from cgroup path
        container_id, runtime, cgroup_path = _extract_container_id_from_cgroup(
            cgroup_content
        )
        if not container_id:
            # Not a containerized process
            info = ContainerInfo(
                cgroup_path=cgroup_path,
                pid_namespace=_extract_pid_namespace(pid),
            )
            self._set_cached(cache_key, info)
            return info

        # Step 3: Extract K8s pod UID if present
        k8s_pod_uid = _extract_k8s_pod_uid(cgroup_content)

        # Step 4: Query container runtime for details
        container_name = ""
        image = ""
        k8s_namespace = ""
        k8s_pod_name = ""

        runtime_info = self._query_runtime(container_id, runtime)
        if runtime_info is not None:
            container_name = runtime_info.get("container_name", "")
            image = runtime_info.get("image", "")
            k8s_namespace = runtime_info.get("k8s_namespace", "")
            k8s_pod_name = runtime_info.get("k8s_pod_name", "")

        pid_ns = _extract_pid_namespace(pid)

        info = ContainerInfo(
            container_id=container_id[:12],
            container_name=container_name,
            image=image,
            k8s_namespace=k8s_namespace,
            k8s_pod_name=k8s_pod_name,
            runtime=runtime,
            cgroup_path=cgroup_path,
            pid_namespace=pid_ns,
        )
        self._set_cached(cache_key, info)
        return info

    def _query_runtime(
        self, container_id: str, runtime: str
    ) -> Optional[Dict[str, str]]:
        """Query the container runtime for name, image, and K8s labels."""
        # Try Docker first
        if self._docker.available:
            data = self._docker.inspect_container(container_id)
            if data is not None:
                return self._parse_docker_inspect(data)

        # Try crictl for CRI-O / containerd
        if self._crictl.available:
            data = self._crictl.inspect_container(container_id)
            if data is not None:
                return self._parse_crictl_inspect(data)

        return None

    @staticmethod
    def _parse_docker_inspect(data: Dict[str, Any]) -> Dict[str, str]:
        """Extract enrichment fields from Docker inspect JSON."""
        config = data.get("Config", {})
        labels = config.get("Labels", {})
        name = data.get("Name", "").lstrip("/")
        image = config.get("Image", "")

        return {
            "container_name": name,
            "image": image,
            "k8s_namespace": labels.get(
                "io.kubernetes.pod.namespace", ""
            ),
            "k8s_pod_name": labels.get("io.kubernetes.pod.name", ""),
        }

    @staticmethod
    def _parse_crictl_inspect(data: Dict[str, Any]) -> Dict[str, str]:
        """Extract enrichment fields from crictl inspect JSON."""
        status = data.get("status", {})
        metadata = status.get("metadata", {})
        image_ref = status.get("image", {}).get("image", "")
        labels = status.get("labels", {})

        return {
            "container_name": metadata.get("name", ""),
            "image": image_ref,
            "k8s_namespace": labels.get(
                "io.kubernetes.pod.namespace", ""
            ),
            "k8s_pod_name": labels.get("io.kubernetes.pod.name", ""),
        }

    @staticmethod
    def _simulate_enrichment(pid: int, cgroup_id: int) -> ContainerInfo:
        """
        Generate synthetic container metadata for non-Linux testing.
        """
        if cgroup_id == 0:
            return _EMPTY_INFO
        fake_id = f"{cgroup_id:012x}{'a' * 52}"
        return ContainerInfo(
            container_id=fake_id[:12],
            container_name=f"sim-container-{cgroup_id}",
            image=f"sim-image:{cgroup_id}",
            k8s_namespace="default" if cgroup_id > 100 else "",
            k8s_pod_name=f"sim-pod-{pid}" if cgroup_id > 100 else "",
            runtime="simulated",
            cgroup_path=f"/kubepods/pod-{cgroup_id}/docker-{fake_id[:12]}",
            pid_namespace=f"pid:[{4026531836 + cgroup_id}]",
        )

    def clear_cache(self) -> None:
        """Flush the enrichment cache."""
        self._cache.clear()

    def enrich_batch(
        self, entries: List[Tuple[int, int]]
    ) -> List[ContainerInfo]:
        """
        Enrich multiple PID/cgroup pairs.

        Args:
            entries: List of (pid, cgroup_id) tuples.

        Returns:
            List of ContainerInfo in the same order.
        """
        return [self.enrich(pid, cid) for pid, cid in entries]
