"""
K-Valkyrie Subgraph to LLM Prompt Translator
Transforms anomalous k-hop PyG subgraphs, attention weights, and process trees
into structured forensic prompts for local LLM hot-patch synthesis.
"""

from __future__ import annotations
import json
from typing import Any, Dict, List


class SubgraphPromptTranslator:
    """Serializes Graph Neural Network anomaly contexts into LLM prompts."""

    @staticmethod
    def format_prompt(
        scored_subgraph_result: Dict[str, Any],
        incident_metadata: Dict[str, Any] | None = None,
    ) -> str:
        meta = incident_metadata or {}
        trigger = scored_subgraph_result.get("trigger_node", "Unknown")
        max_score = scored_subgraph_result.get("max_edge_anomaly_score", 0.0)
        edges = scored_subgraph_result.get("top_anomalous_edges", [])
        total_nodes = scored_subgraph_result.get("subgraph_nodes_count", 0)
        total_edges = scored_subgraph_result.get("subgraph_edges_count", 0)

        lines = [
            "# INCIDENT TELEMETRY PAYLOAD: ANOMALOUS CAUSAL PROVENANCE SUBGRAPH",
            f"- Trigger Node: {trigger}",
            f"- GATv2 Peak Anomaly Score: {max_score:.4f}",
            f"- Causal Subgraph Dimensions: {total_nodes} entities, {total_edges} transitions",
            "",
            "## RANKED CAUSAL TRANSITIONS (BY GATv2 ATTENTION & ANOMALY WEIGHT):",
        ]

        for idx, edge in enumerate(edges, 1):
            src = edge.get("src", "src")
            dst = edge.get("dst", "dst")
            syscall = edge.get("syscall", "unknown")
            score = edge.get("anomaly_score", 0.0)
            attn = edge.get("gat_attention_weight", 0.0)
            lines.append(
                f"{idx}. [{src}] ---({syscall})---> [{dst}] "
                f"(Anomaly Score: {score:.4f}, Attention Weight: {attn:.4f})"
            )

        lines.extend([
            "",
            "## CONTEXTUAL PROCESS & NAMESPACE STATE:",
            f"- Container/cgroup ID: {meta.get('cgroup_id', 'host/root')}",
            f"- Effective UID: {meta.get('uid', '0 (root)')}",
            f"- Target Inode / Resource: {meta.get('inode', 'N/A')}",
            f"- Current Kernel Containment: Process frozen under SIGSTOP via eBPF LSM",
            "",
            "## OBJECTIVE:",
            "Analyze the causal transitions above. Synthesize a surgical, least-privilege Seccomp-BPF",
            "profile and eBPF LSM rule that blocks this attack chain while allowing benign parent services to resume.",
            "Return valid JSON strictly matching the system instructions schema.",
        ])

        return "\n".join(lines)
