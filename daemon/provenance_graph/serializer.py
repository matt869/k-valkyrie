"""
K-Valkyrie Provenance Graph Serializer
Converts NetworkX subgraphs to PyTorch Geometric Data objects and JSON-
serializable dictionaries for WebSocket streaming and reconstruction.
"""

from __future__ import annotations

import json
import logging
import math
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx
import torch

try:
    from torch_geometric.data import Data as PyGData
except ImportError:
    class PyGData:  # type: ignore[no-redef]
        """Lightweight fallback when torch_geometric is not installed."""
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
            nn = self.x.size(0) if self.x is not None else 0
            ne = self.edge_index.size(1) if self.edge_index is not None else 0
            return f"Data(x=[{nn}, ...], edge_index=[2, {ne}])"

logger = logging.getLogger(__name__)

# Feature dimensions (must match graph_builder.py)
NODE_FEAT_DIM = 16
EDGE_FEAT_DIM = 8

# Node type mapping for one-hot encoding
NODE_TYPE_MAP: Dict[str, int] = {
    "process": 0,
    "file": 1,
    "memfd": 2,
    "socket": 3,
}

# Edge type (syscall) mapping for one-hot encoding
EDGE_TYPE_MAP: Dict[str, int] = {
    "execve": 0,
    "memfd_create": 1,
    "ptrace": 2,
    "lsm_bprm_check": 3,
    "lsm_access": 4,
    "clone/execve": 5,
    "unknown": 6,
}


def _encode_node_features(
    node_data: Dict[str, Any],
    dim: int = NODE_FEAT_DIM,
) -> List[float]:
    """
    Encode node attributes into a fixed-dimension feature vector.

    Dimension layout (16-dim):
        [0-3]  One-hot node type (process / file / memfd / socket)
        [4]    is_root (uid == 0)
        [5]    in_container (cgroup_id != 0)
        [6]    is_quarantined
        [7]    filename entropy (normalized)
        [8-15] Reserved / padding
    """
    # If the node already has pre-computed features, use them
    existing = node_data.get("features")
    if existing is not None and len(existing) == dim:
        return list(existing)

    vec = [0.0] * dim

    # Node type one-hot
    ntype = node_data.get("node_type", "process")
    type_idx = NODE_TYPE_MAP.get(ntype, 0)
    if type_idx < 4:
        vec[type_idx] = 1.0

    # Root flag
    uid = node_data.get("uid", 1000)
    vec[4] = 1.0 if uid == 0 else 0.0

    # Container flag
    cgroup_id = node_data.get("cgroup_id", 0)
    vec[5] = 1.0 if cgroup_id != 0 else 0.0

    # Quarantined flag
    vec[6] = float(node_data.get("is_quarantined", 0.0))

    # Path / filename entropy
    path = node_data.get("path", "") or node_data.get("comm", "") or ""
    vec[7] = _string_entropy(path) if path else 0.5

    return vec


def _encode_edge_features(
    edge_data: Dict[str, Any],
    dim: int = EDGE_FEAT_DIM,
) -> List[float]:
    """
    Encode edge attributes into a fixed-dimension feature vector.

    Dimension layout (8-dim):
        [0-5]  One-hot syscall type
        [6]    action_taken (numeric)
        [7]    Normalized causal weight
    """
    existing = edge_data.get("features")
    if existing is not None and len(existing) == dim:
        return list(existing)

    vec = [0.0] * dim

    syscall_name = edge_data.get("syscall_name", "unknown")
    idx = EDGE_TYPE_MAP.get(syscall_name, 6)
    if idx < 6:
        vec[idx] = 1.0
    else:
        vec[5] = 1.0  # "other" bucket

    vec[6] = float(edge_data.get("action_taken", edge_data.get("action", 0)))
    vec[7] = 1.0

    return vec


def _string_entropy(s: str) -> float:
    """Compute Shannon entropy of a string, normalized to [0, 1]."""
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    max_entropy = math.log2(max(len(freq), 2))
    return min(entropy / max_entropy, 1.0) if max_entropy > 0 else 0.0


class ProvenanceSerializer:
    """
    Serializes and deserializes provenance subgraphs between NetworkX,
    PyTorch Geometric, and JSON formats.

    Usage::

        serializer = ProvenanceSerializer()

        # NetworkX -> PyG Data
        pyg_data = serializer.nx_to_pyg(subgraph, trigger_node="Process:4192")

        # PyG Data -> JSON dict
        json_dict = serializer.pyg_to_json(pyg_data)

        # JSON dict -> PyG Data
        reconstructed = serializer.deserialize_from_json(json_dict)

        # NetworkX -> JSON dict
        json_dict = serializer.nx_to_json(subgraph)
    """

    def __init__(
        self,
        node_feat_dim: int = NODE_FEAT_DIM,
        edge_feat_dim: int = EDGE_FEAT_DIM,
    ) -> None:
        self._node_feat_dim = node_feat_dim
        self._edge_feat_dim = edge_feat_dim

    def nx_to_pyg(
        self,
        graph: nx.DiGraph | nx.MultiDiGraph,
        *,
        trigger_node: Optional[str] = None,
    ) -> PyGData:
        """
        Convert a NetworkX graph to a PyTorch Geometric Data object.

        Args:
            graph: Input directed graph (DiGraph or MultiDiGraph).
            trigger_node: Optional anchor node ID for marking trigger index.

        Returns:
            PyGData with x, edge_index, edge_attr, node_names, edge_metadata.
        """
        node_list = list(graph.nodes())
        if not node_list:
            return PyGData(
                x=torch.zeros((0, self._node_feat_dim), dtype=torch.float32),
                edge_index=torch.empty((2, 0), dtype=torch.long),
                edge_attr=torch.empty((0, self._edge_feat_dim), dtype=torch.float32),
                node_names=[],
                edge_metadata=[],
                trigger_node=trigger_node or "",
                trigger_idx=-1,
            )

        node_to_idx = {nid: i for i, nid in enumerate(node_list)}
        trigger_idx = node_to_idx.get(trigger_node, -1) if trigger_node else -1

        # Node features
        x_list = []
        for nid in node_list:
            ndata = dict(graph.nodes[nid])
            feat = _encode_node_features(ndata, self._node_feat_dim)
            x_list.append(feat)
        x = torch.tensor(x_list, dtype=torch.float32)

        # Edges
        src_list: List[int] = []
        dst_list: List[int] = []
        edge_attr_list: List[List[float]] = []
        edge_metadata: List[Dict[str, Any]] = []

        if isinstance(graph, nx.MultiDiGraph):
            edges_iter = graph.edges(keys=True, data=True)
            for u, v, key, data in edges_iter:
                src_list.append(node_to_idx[u])
                dst_list.append(node_to_idx[v])
                edge_attr_list.append(
                    _encode_edge_features(data, self._edge_feat_dim)
                )
                edge_metadata.append({
                    "src": u,
                    "dst": v,
                    "edge_key": key,
                    "syscall_name": data.get("syscall_name", "unknown"),
                    "timestamp_ns": data.get("timestamp_ns", 0),
                })
        else:
            for u, v, data in graph.edges(data=True):
                src_list.append(node_to_idx[u])
                dst_list.append(node_to_idx[v])
                edge_attr_list.append(
                    _encode_edge_features(data, self._edge_feat_dim)
                )
                edge_metadata.append({
                    "src": u,
                    "dst": v,
                    "syscall_name": data.get("syscall_name", "unknown"),
                    "timestamp_ns": data.get("timestamp_ns", 0),
                })

        if src_list:
            edge_index = torch.tensor([src_list, dst_list], dtype=torch.long)
            edge_attr = torch.tensor(edge_attr_list, dtype=torch.float32)
        else:
            edge_index = torch.empty((2, 0), dtype=torch.long)
            edge_attr = torch.empty((0, self._edge_feat_dim), dtype=torch.float32)

        return PyGData(
            x=x,
            edge_index=edge_index,
            edge_attr=edge_attr,
            node_names=node_list,
            trigger_node=trigger_node or "",
            trigger_idx=trigger_idx,
            edge_metadata=edge_metadata,
        )

    def pyg_to_json(self, data: PyGData) -> Dict[str, Any]:
        """
        Convert a PyTorch Geometric Data object to a JSON-serializable dict.

        Suitable for WebSocket streaming to the Cytoscape.js dashboard.
        """
        node_names = getattr(data, "node_names", [])
        edge_metadata = getattr(data, "edge_metadata", [])

        # Node features to nested lists
        if data.x is not None:
            x_list = data.x.cpu().tolist()
        else:
            x_list = []

        # Edge index
        if data.edge_index is not None and data.edge_index.numel() > 0:
            ei = data.edge_index.cpu().tolist()
        else:
            ei = [[], []]

        # Edge attributes
        if data.edge_attr is not None and data.edge_attr.numel() > 0:
            ea = data.edge_attr.cpu().tolist()
        else:
            ea = []

        return {
            "node_features": x_list,
            "node_names": node_names,
            "edge_index": ei,
            "edge_attr": ea,
            "edge_metadata": edge_metadata,
            "trigger_node": getattr(data, "trigger_node", ""),
            "trigger_idx": getattr(data, "trigger_idx", -1),
            "num_nodes": len(x_list),
            "num_edges": len(ei[0]) if ei and ei[0] else 0,
            "node_feat_dim": self._node_feat_dim,
            "edge_feat_dim": self._edge_feat_dim,
        }

    def deserialize_from_json(self, json_data: Dict[str, Any]) -> PyGData:
        """
        Reconstruct a PyG Data object from a JSON dictionary.

        Args:
            json_data: Dictionary produced by ``pyg_to_json()``.

        Returns:
            Reconstructed PyGData.
        """
        x_list = json_data.get("node_features", [])
        ei_raw = json_data.get("edge_index", [[], []])
        ea_list = json_data.get("edge_attr", [])
        node_names = json_data.get("node_names", [])
        edge_metadata = json_data.get("edge_metadata", [])
        trigger_node = json_data.get("trigger_node", "")
        trigger_idx = json_data.get("trigger_idx", -1)

        feat_dim = json_data.get("node_feat_dim", self._node_feat_dim)
        edge_dim = json_data.get("edge_feat_dim", self._edge_feat_dim)

        if x_list:
            x = torch.tensor(x_list, dtype=torch.float32)
        else:
            x = torch.zeros((0, feat_dim), dtype=torch.float32)

        if ei_raw and ei_raw[0]:
            edge_index = torch.tensor(ei_raw, dtype=torch.long)
        else:
            edge_index = torch.empty((2, 0), dtype=torch.long)

        if ea_list:
            edge_attr = torch.tensor(ea_list, dtype=torch.float32)
        else:
            edge_attr = torch.empty((0, edge_dim), dtype=torch.float32)

        return PyGData(
            x=x,
            edge_index=edge_index,
            edge_attr=edge_attr,
            node_names=node_names,
            edge_metadata=edge_metadata,
            trigger_node=trigger_node,
            trigger_idx=trigger_idx,
        )

    def nx_to_json(
        self,
        graph: nx.DiGraph | nx.MultiDiGraph,
        *,
        trigger_node: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Convenience: convert NetworkX graph directly to JSON dict.
        """
        pyg_data = self.nx_to_pyg(graph, trigger_node=trigger_node)
        return self.pyg_to_json(pyg_data)

    def json_to_nx(self, json_data: Dict[str, Any]) -> nx.DiGraph:
        """
        Reconstruct a NetworkX DiGraph from a JSON dictionary.

        Useful for round-trip serialization via WebSocket.
        """
        graph = nx.DiGraph()
        node_names = json_data.get("node_names", [])
        x_list = json_data.get("node_features", [])
        ei_raw = json_data.get("edge_index", [[], []])
        ea_list = json_data.get("edge_attr", [])
        edge_metadata = json_data.get("edge_metadata", [])

        for i, nid in enumerate(node_names):
            attrs: Dict[str, Any] = {}
            if i < len(x_list):
                attrs["features"] = x_list[i]
            graph.add_node(nid, **attrs)

        if ei_raw and len(ei_raw) == 2:
            for idx in range(len(ei_raw[0])):
                src_idx = ei_raw[0][idx]
                dst_idx = ei_raw[1][idx]
                if src_idx < len(node_names) and dst_idx < len(node_names):
                    src_name = node_names[src_idx]
                    dst_name = node_names[dst_idx]
                    attrs = {}
                    if idx < len(ea_list):
                        attrs["features"] = ea_list[idx]
                    if idx < len(edge_metadata):
                        attrs.update(edge_metadata[idx])
                    graph.add_edge(src_name, dst_name, **attrs)

        return graph

    @staticmethod
    def pyg_to_json_string(data: PyGData) -> str:
        """Serialize PyG Data to a JSON string."""
        serializer = ProvenanceSerializer()
        return json.dumps(serializer.pyg_to_json(data), separators=(",", ":"))

    @staticmethod
    def json_string_to_pyg(s: str) -> PyGData:
        """Deserialize a JSON string back to PyG Data."""
        serializer = ProvenanceSerializer()
        return serializer.deserialize_from_json(json.loads(s))


# Compatibility alias
SubgraphSerializer = ProvenanceSerializer
