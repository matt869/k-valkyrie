"""
K-Valkyrie Provenance Graph Builder & Temporal Subgraph Sampler
Maintains a sliding-window Temporal Directed Acyclic Graph (DAG) of kernel syscalls
and samples k-hop causal neighborhoods for Spatio-Temporal GNN inference.
"""

from __future__ import annotations
import ctypes
import math
import os
import time
from typing import Dict, List, Optional, Set, Tuple, Any

import networkx as nx
import torch

try:
    from torch_geometric.data import Data as PyGData
except ImportError:
    # Lightweight fallback dataclass if torch_geometric is not yet installed
    class PyGData:  # type: ignore
        def __init__(self, x=None, edge_index=None, edge_attr=None, **kwargs):
            self.x = x
            self.edge_index = edge_index
            self.edge_attr = edge_attr
            for k, v in kwargs.items():
                setattr(self, k, v)

        def to(self, device):
            if hasattr(self.x, "to"):
                self.x = self.x.to(device)
            if hasattr(self.edge_index, "to"):
                self.edge_index = self.edge_index.to(device)
            if hasattr(self.edge_attr, "to") and self.edge_attr is not None:
                self.edge_attr = self.edge_attr.to(device)
            return self

        def __repr__(self):
            num_nodes = self.x.size(0) if self.x is not None else 0
            num_edges = self.edge_index.size(1) if self.edge_index is not None else 0
            return f"Data(x=[{num_nodes}, {self.x.size(1) if self.x is not None else 0}], edge_index=[2, {num_edges}])"


# ============================================================================
# Ctypes Struct Matching `headers/common_events.h`
# ============================================================================
class SyscallEventRaw(ctypes.Structure):
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


# Constants matching common_events.h
VALKYRIE_SYS_EXECVE = 59
VALKYRIE_SYS_PTRACE = 101
VALKYRIE_SYS_MEMFD_CREATE = 319
VALKYRIE_SYS_EXECVEAT = 322
VALKYRIE_LSM_BPRM_CHECK = 1001
VALKYRIE_LSM_FILE_OPEN = 1002

NODE_FEAT_DIM = 16
EDGE_FEAT_DIM = 8

SENSITIVE_TARGETS = {
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/proc/kallsyms",
    "/root/.ssh",
    "/var/run/docker.sock",
}


class ProvenanceGraphBuilder:
    """
    Ingests continuous eBPF telemetry events, maintains a sliding-window
    Temporal Directed Causal Graph, and extracts k-hop PyG subgraphs on anomalous triggers.
    """

    def __init__(self, window_duration_ns: int = 120_000_000_000):  # 120 seconds
        self.window_duration_ns = window_duration_ns
        self.graph = nx.MultiDiGraph()
        self.total_events_ingested = 0
        self.quarantined_pids: Set[int] = set()

    def parse_event_bytes(self, raw_bytes: bytes) -> SyscallEventRaw:
        """Parses binary payload from eBPF ring buffer into SyscallEventRaw struct."""
        event = SyscallEventRaw()
        ctypes.memmove(ctypes.byref(event), raw_bytes, min(len(raw_bytes), ctypes.sizeof(event)))
        return event

    def process_event(self, event: SyscallEventRaw | Dict[str, Any]) -> Tuple[bool, Optional[str], Optional[PyGData]]:
        """
        Consumes an event, updates the causal provenance graph, and checks for high-risk triggers.
        Returns:
            (is_high_risk, trigger_node_id, pyg_subgraph_data)
        """
        self.total_events_ingested += 1

        if isinstance(event, dict):
            # Support mock / json dictionary events
            ts = event.get("timestamp_ns", int(time.time_ns()))
            pid = event.get("pid", 0)
            ppid = event.get("ppid", 0)
            uid = event.get("uid", 0)
            gid = event.get("gid", 0)
            cgroup_id = event.get("cgroup_id", 0)
            syscall_id = event.get("syscall_id", 0)
            target_pid = event.get("target_pid", 0)
            fd_flags = event.get("fd_flags", 0)
            inode = event.get("inode", 0)
            action = event.get("action_taken", 0)
            comm = event.get("comm", "")
            filename = event.get("filename", "")
        else:
            ts = event.timestamp_ns
            pid = event.pid
            ppid = event.ppid
            uid = event.uid
            gid = event.gid
            cgroup_id = event.cgroup_id
            syscall_id = event.syscall_id
            target_pid = event.target_pid
            fd_flags = event.fd_flags
            inode = event.inode
            action = event.action_taken
            comm = event.comm.decode("utf-8", errors="replace").strip("\x00")
            filename = event.filename.decode("utf-8", errors="replace").strip("\x00")

        if action >= 2:
            self.quarantined_pids.add(pid)

        # ---------------------------------------------------------------------
        # 1. Update / Create Process Node
        # ---------------------------------------------------------------------
        proc_node = f"Process:{pid}"
        is_root = 1.0 if uid == 0 else 0.0
        in_container = 1.0 if cgroup_id != 0 else 0.0
        is_quarantined = 1.0 if pid in self.quarantined_pids else 0.0

        if not self.graph.has_node(proc_node):
            self.graph.add_node(
                proc_node,
                node_type="process",
                pid=pid,
                ppid=ppid,
                uid=uid,
                gid=gid,
                cgroup_id=cgroup_id,
                comm=comm,
                created_ns=ts,
                last_seen_ns=ts,
                features=self._encode_node_features(
                    node_type_idx=0, is_root=is_root, in_container=in_container, is_quarantined=is_quarantined
                ),
            )
        else:
            self.graph.nodes[proc_node]["last_seen_ns"] = ts
            self.graph.nodes[proc_node]["comm"] = comm
            self.graph.nodes[proc_node]["features"] = self._encode_node_features(
                node_type_idx=0, is_root=is_root, in_container=in_container, is_quarantined=is_quarantined
            )

        # Connect Parent PID if valid
        if ppid > 0:
            parent_node = f"Process:{ppid}"
            if not self.graph.has_node(parent_node):
                self.graph.add_node(
                    parent_node,
                    node_type="process",
                    pid=ppid,
                    ppid=0,
                    uid=uid,
                    gid=gid,
                    cgroup_id=cgroup_id,
                    comm="<parent>",
                    created_ns=ts,
                    last_seen_ns=ts,
                    features=self._encode_node_features(
                        node_type_idx=0, is_root=is_root, in_container=in_container, is_quarantined=0.0
                    ),
                )
            if not self.graph.has_edge(parent_node, proc_node):
                edge_feat = self._encode_edge_features(syscall_id=VALKYRIE_SYS_EXECVE, action=action)
                self.graph.add_edge(
                    parent_node,
                    proc_node,
                    key="spawn",
                    syscall_id=VALKYRIE_SYS_EXECVE,
                    syscall_name="clone/execve",
                    timestamp_ns=ts,
                    features=edge_feat,
                )

        # ---------------------------------------------------------------------
        # 2. Add Causal Edges Based on Syscall Type
        # ---------------------------------------------------------------------
        high_risk = False
        trigger_node = None

        if syscall_id in (VALKYRIE_SYS_EXECVE, VALKYRIE_SYS_EXECVEAT):
            file_node = f"File:{filename}" if filename else f"File:inode_{inode}"
            self._ensure_file_node(file_node, inode, filename, ts, in_container)
            edge_feat = self._encode_edge_features(syscall_id, action)
            self.graph.add_edge(
                proc_node,
                file_node,
                key=f"exec_{ts}",
                syscall_id=syscall_id,
                syscall_name="execve",
                timestamp_ns=ts,
                features=edge_feat,
            )
            # Check for suspicious execution targets
            if "memfd:" in filename or "/proc/self/fd" in filename or "/dev/shm" in filename:
                high_risk = True
                trigger_node = proc_node

        elif syscall_id == VALKYRIE_SYS_MEMFD_CREATE:
            memfd_node = f"MemFD:{filename or 'anon_elf'}:{pid}"
            if not self.graph.has_node(memfd_node):
                self.graph.add_node(
                    memfd_node,
                    node_type="memfd",
                    name=filename,
                    creator_pid=pid,
                    created_ns=ts,
                    last_seen_ns=ts,
                    features=self._encode_node_features(
                        node_type_idx=2, is_root=is_root, in_container=in_container, is_quarantined=0.0
                    ),
                )
            edge_feat = self._encode_edge_features(syscall_id, action)
            self.graph.add_edge(
                proc_node,
                memfd_node,
                key=f"memfd_{ts}",
                syscall_id=syscall_id,
                syscall_name="memfd_create",
                timestamp_ns=ts,
                features=edge_feat,
            )
            # memfd_create is an anomalous fileless execution precursor
            high_risk = True
            trigger_node = proc_node

        elif syscall_id == VALKYRIE_SYS_PTRACE:
            target_node = f"Process:{target_pid}"
            if not self.graph.has_node(target_node):
                self.graph.add_node(
                    target_node,
                    node_type="process",
                    pid=target_pid,
                    ppid=0,
                    uid=0,
                    gid=0,
                    cgroup_id=cgroup_id,
                    comm="<ptrace_target>",
                    created_ns=ts,
                    last_seen_ns=ts,
                    features=self._encode_node_features(
                        node_type_idx=0, is_root=0.0, in_container=in_container, is_quarantined=0.0
                    ),
                )
            edge_feat = self._encode_edge_features(syscall_id, action)
            self.graph.add_edge(
                proc_node,
                target_node,
                key=f"ptrace_{ts}",
                syscall_id=syscall_id,
                syscall_name="ptrace",
                timestamp_ns=ts,
                features=edge_feat,
            )
            # ptrace cross-process memory manipulation is high-risk
            high_risk = True
            trigger_node = proc_node

        elif syscall_id in (VALKYRIE_LSM_FILE_OPEN, VALKYRIE_LSM_BPRM_CHECK):
            file_node = f"File:{filename}" if filename else f"File:inode_{inode}"
            self._ensure_file_node(file_node, inode, filename, ts, in_container)
            edge_feat = self._encode_edge_features(syscall_id, action)
            self.graph.add_edge(
                proc_node,
                file_node,
                key=f"open_{ts}",
                syscall_id=syscall_id,
                syscall_name="lsm_access",
                timestamp_ns=ts,
                features=edge_feat,
            )
            for sensitive in SENSITIVE_TARGETS:
                if sensitive in filename:
                    high_risk = True
                    trigger_node = proc_node
                    break

        # Periodic sliding window cleanup every 100 events
        if self.total_events_ingested % 100 == 0:
            self.prune_sliding_window(ts)

        # ---------------------------------------------------------------------
        # 3. Export Subgraph Tensor if High Risk
        # ---------------------------------------------------------------------
        pyg_data = None
        if high_risk and trigger_node:
            pyg_data = self.sample_khop_subgraph(trigger_node, k=3)

        return high_risk, trigger_node, pyg_data

    def _ensure_file_node(self, file_node: str, inode: int, path: str, ts: int, in_container: float):
        if not self.graph.has_node(file_node):
            self.graph.add_node(
                file_node,
                node_type="file",
                inode=inode,
                path=path,
                created_ns=ts,
                last_seen_ns=ts,
                features=self._encode_node_features(
                    node_type_idx=1, is_root=0.0, in_container=in_container, is_quarantined=0.0
                ),
            )
        else:
            self.graph.nodes[file_node]["last_seen_ns"] = ts

    def _encode_node_features(
        self, node_type_idx: int, is_root: float, in_container: float, is_quarantined: float
    ) -> List[float]:
        # Dimension 16: [one_hot_types(4), root(1), container(1), quarantined(1), entropy(1), padding(8)]
        vec = [0.0] * NODE_FEAT_DIM
        vec[node_type_idx] = 1.0
        vec[4] = is_root
        vec[5] = in_container
        vec[6] = is_quarantined
        vec[7] = 0.5  # base node entropy
        return vec

    def _encode_edge_features(self, syscall_id: int, action: int) -> List[float]:
        # Dimension 8: [one_hot_syscalls(6), action(1), time_weight(1)]
        vec = [0.0] * EDGE_FEAT_DIM
        if syscall_id == VALKYRIE_SYS_EXECVE:
            vec[0] = 1.0
        elif syscall_id == VALKYRIE_SYS_MEMFD_CREATE:
            vec[1] = 1.0
        elif syscall_id == VALKYRIE_SYS_PTRACE:
            vec[2] = 1.0
        elif syscall_id == VALKYRIE_LSM_BPRM_CHECK:
            vec[3] = 1.0
        elif syscall_id == VALKYRIE_LSM_FILE_OPEN:
            vec[4] = 1.0
        else:
            vec[5] = 1.0
        vec[6] = float(action)
        vec[7] = 1.0  # Normalized causal weight
        return vec

    def prune_sliding_window(self, current_time_ns: int):
        """Purges edges and nodes outside the sliding window unless protected."""
        cutoff_ns = current_time_ns - self.window_duration_ns
        expired_nodes = []
        for node, data in self.graph.nodes(data=True):
            last_seen = data.get("last_seen_ns", 0)
            pid = data.get("pid", -1)
            if last_seen < cutoff_ns and pid not in self.quarantined_pids:
                expired_nodes.append(node)

        for n in expired_nodes:
            self.graph.remove_node(n)

    def sample_khop_subgraph(self, trigger_node: str, k: int = 3) -> PyGData:
        """
        Extracts the k-hop causal neighborhood around trigger_node
        and returns a standardized PyTorch Geometric Data tensor object.
        """
        if not self.graph.has_node(trigger_node):
            # Fallback single node graph
            x = torch.zeros((1, NODE_FEAT_DIM), dtype=torch.float32)
            edge_index = torch.empty((2, 0), dtype=torch.long)
            edge_attr = torch.empty((0, EDGE_FEAT_DIM), dtype=torch.float32)
            return PyGData(x=x, edge_index=edge_index, edge_attr=edge_attr, node_names=[trigger_node], trigger_idx=0)

        # Extract k-hop neighborhood using undirected view for complete causal context
        undirected_g = self.graph.to_undirected(as_view=True)
        subgraph_nodes = set(nx.single_source_shortest_path_length(undirected_g, trigger_node, cutoff=k).keys())

        # Induce subgraph on the original MultiDiGraph
        subgraph: nx.MultiDiGraph = self.graph.subgraph(subgraph_nodes)

        # Build consistent node indexing
        node_list = list(subgraph.nodes())
        node_to_idx = {node_id: idx for idx, node_id in enumerate(node_list)}
        trigger_idx = node_to_idx[trigger_node]

        # Construct Node Features Tensor [N, NODE_FEAT_DIM]
        x_list = []
        for n in node_list:
            feat = subgraph.nodes[n].get("features", [0.0] * NODE_FEAT_DIM)
            x_list.append(feat)
        x_tensor = torch.tensor(x_list, dtype=torch.float32)

        # Construct Edges & Edge Attributes Tensors [2, E], [E, EDGE_FEAT_DIM]
        edge_src_list = []
        edge_dst_list = []
        edge_attr_list = []
        edge_metadata = []

        for u, v, edge_key, data in subgraph.edges(keys=True, data=True):
            src_idx = node_to_idx[u]
            dst_idx = node_to_idx[v]
            edge_src_list.append(src_idx)
            edge_dst_list.append(dst_idx)
            edge_attr_list.append(data.get("features", [0.0] * EDGE_FEAT_DIM))
            edge_metadata.append(
                {
                    "src": u,
                    "dst": v,
                    "syscall_name": data.get("syscall_name", "unknown"),
                    "timestamp_ns": data.get("timestamp_ns", 0),
                }
            )

        if edge_src_list:
            edge_index = torch.tensor([edge_src_list, edge_dst_list], dtype=torch.long)
            edge_attr = torch.tensor(edge_attr_list, dtype=torch.float32)
        else:
            edge_index = torch.empty((2, 0), dtype=torch.long)
            edge_attr = torch.empty((0, EDGE_FEAT_DIM), dtype=torch.float32)

        pyg_data = PyGData(
            x=x_tensor,
            edge_index=edge_index,
            edge_attr=edge_attr,
            node_names=node_list,
            trigger_idx=trigger_idx,
            trigger_node=trigger_node,
            edge_metadata=edge_metadata,
        )

        return pyg_data
