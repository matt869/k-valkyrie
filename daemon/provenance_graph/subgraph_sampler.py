"""
K-Valkyrie Subgraph Sampler
Extracts k-hop causal neighborhoods from the provenance graph with temporal
filtering, edge type filtering, and configurable size limits.
"""

from __future__ import annotations

import logging
from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx

logger = logging.getLogger(__name__)


class SubgraphSampler:
    """
    Extracts k-hop causal neighborhoods from a NetworkX MultiDiGraph
    (as produced by ``ProvenanceGraphBuilder``).

    Supports:
    - Temporal filtering: only edges within a specified time window.
    - Edge type filtering: restrict to specific syscall names.
    - Max subgraph size limits: cap on node/edge count.

    Usage::

        sampler = SubgraphSampler(graph=builder.graph)
        sub = sampler.sample(
            seed_node="Process:4192",
            k=3,
            time_window_ns=(start, end),
            edge_types={"execve", "memfd_create"},
            max_nodes=200,
        )
    """

    def __init__(
        self,
        graph: nx.MultiDiGraph,
    ) -> None:
        """
        Args:
            graph: The provenance MultiDiGraph (from ProvenanceGraphBuilder).
        """
        self._graph = graph

    @property
    def graph(self) -> nx.MultiDiGraph:
        """Reference to the underlying provenance graph."""
        return self._graph

    @graph.setter
    def graph(self, g: nx.MultiDiGraph) -> None:
        self._graph = g

    def sample(
        self,
        seed_node: str,
        k: int = 3,
        *,
        time_window_ns: Optional[Tuple[int, int]] = None,
        edge_types: Optional[Set[str]] = None,
        max_nodes: int = 500,
        max_edges: int = 2000,
        direction: str = "both",
    ) -> nx.DiGraph:
        """
        Extract a k-hop causal neighborhood from the provenance graph.

        Args:
            seed_node: The anchor node from which to expand.
            k: Number of hops to expand.
            time_window_ns: Optional (start_ns, end_ns) tuple; only edges
                with ``timestamp_ns`` within this window are traversed.
            edge_types: Optional set of ``syscall_name`` values to include.
                If None, all edge types are included.
            max_nodes: Maximum number of nodes in the subgraph.
            max_edges: Maximum number of edges in the subgraph.
            direction: ``"both"`` (default), ``"forward"`` (successors only),
                or ``"backward"`` (predecessors only).

        Returns:
            A ``nx.DiGraph`` containing the sampled subgraph with original
            node/edge attributes preserved. Returns an empty DiGraph if the
            seed node is not present.
        """
        result = nx.DiGraph()

        if not self._graph.has_node(seed_node):
            logger.warning("Seed node %s not found in graph", seed_node)
            return result

        # BFS expansion
        visited_nodes: Set[str] = {seed_node}
        frontier: deque[Tuple[str, int]] = deque([(seed_node, 0)])
        collected_edges: List[Tuple[str, str, Dict[str, Any]]] = []

        while frontier:
            if len(visited_nodes) >= max_nodes:
                break

            node, depth = frontier.popleft()
            if depth >= k:
                continue

            # Collect neighbors in the requested direction(s)
            neighbor_edges: List[Tuple[str, str, str, Dict[str, Any]]] = []

            if direction in ("both", "forward"):
                for u, v, key, data in self._graph.out_edges(node, keys=True, data=True):
                    neighbor_edges.append((u, v, key, data))

            if direction in ("both", "backward"):
                for u, v, key, data in self._graph.in_edges(node, keys=True, data=True):
                    neighbor_edges.append((u, v, key, data))

            for u, v, key, data in neighbor_edges:
                # Temporal filter
                if time_window_ns is not None:
                    edge_ts = data.get("timestamp_ns", 0)
                    if edge_ts < time_window_ns[0] or edge_ts > time_window_ns[1]:
                        continue

                # Edge type filter
                if edge_types is not None:
                    syscall_name = data.get("syscall_name", "")
                    if syscall_name not in edge_types:
                        continue

                # Edge count limit
                if len(collected_edges) >= max_edges:
                    break

                # Flatten edge data for DiGraph (discard multi-edge key duplication)
                edge_data = dict(data)
                edge_data["edge_key"] = key
                collected_edges.append((u, v, edge_data))

                # Expand to the neighbor
                neighbor = v if u == node else u
                if neighbor not in visited_nodes:
                    if len(visited_nodes) < max_nodes:
                        visited_nodes.add(neighbor)
                        frontier.append((neighbor, depth + 1))

            if len(collected_edges) >= max_edges:
                break

        # Build the result DiGraph
        for nid in visited_nodes:
            if self._graph.has_node(nid):
                result.add_node(nid, **dict(self._graph.nodes[nid]))
            else:
                result.add_node(nid)

        for u, v, data in collected_edges:
            # DiGraph only supports one edge per (u, v); keep the latest
            if result.has_edge(u, v):
                existing_ts = result.edges[u, v].get("timestamp_ns", 0)
                new_ts = data.get("timestamp_ns", 0)
                if new_ts <= existing_ts:
                    continue
            result.add_edge(u, v, **data)

        logger.debug(
            "Sampled subgraph around %s: %d nodes, %d edges (k=%d)",
            seed_node,
            result.number_of_nodes(),
            result.number_of_edges(),
            k,
        )
        return result

    def sample_temporal_window(
        self,
        start_ns: int,
        end_ns: int,
        *,
        max_nodes: int = 1000,
        max_edges: int = 5000,
    ) -> nx.DiGraph:
        """
        Extract all edges within a temporal window and their endpoint nodes.

        Args:
            start_ns: Start of the time window (inclusive).
            end_ns: End of the time window (inclusive).
            max_nodes: Maximum nodes to include.
            max_edges: Maximum edges to include.

        Returns:
            A DiGraph of the temporal slice.
        """
        result = nx.DiGraph()
        edge_count = 0

        for u, v, key, data in self._graph.edges(keys=True, data=True):
            edge_ts = data.get("timestamp_ns", 0)
            if start_ns <= edge_ts <= end_ns:
                if edge_count >= max_edges:
                    break

                # Ensure nodes are added with attributes
                if not result.has_node(u) and result.number_of_nodes() < max_nodes:
                    result.add_node(u, **dict(self._graph.nodes.get(u, {})))
                if not result.has_node(v) and result.number_of_nodes() < max_nodes:
                    result.add_node(v, **dict(self._graph.nodes.get(v, {})))

                if result.has_node(u) and result.has_node(v):
                    edge_data = dict(data)
                    edge_data["edge_key"] = key
                    if not result.has_edge(u, v):
                        result.add_edge(u, v, **edge_data)
                        edge_count += 1

        return result

    def sample_multi_seed(
        self,
        seed_nodes: List[str],
        k: int = 2,
        *,
        time_window_ns: Optional[Tuple[int, int]] = None,
        edge_types: Optional[Set[str]] = None,
        max_nodes: int = 500,
        max_edges: int = 2000,
    ) -> nx.DiGraph:
        """
        Sample k-hop neighborhoods from multiple seed nodes and merge them.

        Args:
            seed_nodes: List of seed node IDs.
            k: Number of hops per seed.
            time_window_ns: Optional temporal filter.
            edge_types: Optional edge type filter.
            max_nodes: Max nodes in the merged result.
            max_edges: Max edges in the merged result.

        Returns:
            Merged DiGraph of all seed neighborhoods.
        """
        merged = nx.DiGraph()

        for seed in seed_nodes:
            if merged.number_of_nodes() >= max_nodes:
                break

            sub = self.sample(
                seed_node=seed,
                k=k,
                time_window_ns=time_window_ns,
                edge_types=edge_types,
                max_nodes=max_nodes - merged.number_of_nodes(),
                max_edges=max_edges - merged.number_of_edges(),
            )

            for nid, ndata in sub.nodes(data=True):
                if not merged.has_node(nid):
                    merged.add_node(nid, **ndata)

            for u, v, edata in sub.edges(data=True):
                if not merged.has_edge(u, v):
                    merged.add_edge(u, v, **edata)

        return merged

    def get_causal_ancestors(
        self,
        node: str,
        max_depth: int = 10,
    ) -> nx.DiGraph:
        """
        Trace causal ancestry (predecessors) from a node up to max_depth.

        Args:
            node: Starting node.
            max_depth: Maximum traversal depth.

        Returns:
            DiGraph of the ancestor subgraph.
        """
        return self.sample(
            seed_node=node,
            k=max_depth,
            direction="backward",
        )

    def get_causal_descendants(
        self,
        node: str,
        max_depth: int = 10,
    ) -> nx.DiGraph:
        """
        Trace causal effects (successors) from a node up to max_depth.

        Args:
            node: Starting node.
            max_depth: Maximum traversal depth.

        Returns:
            DiGraph of the descendant subgraph.
        """
        return self.sample(
            seed_node=node,
            k=max_depth,
            direction="forward",
        )
