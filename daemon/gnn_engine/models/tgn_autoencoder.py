"""
K-Valkyrie Spatio-Temporal Graph Neural Network Autoencoder
Implements a GATv2-based Provenance Graph Autoencoder that computes node embeddings,
edge anomaly scores (0.0 to 1.0), and attention weights to isolate malicious causal paths.
"""

from __future__ import annotations
import math
from typing import Any, Dict, List, Optional, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F

# Try importing from torch_geometric if installed; otherwise use native GATv2Conv implementation
try:
    from torch_geometric.nn import GATv2Conv as PyGGATv2Conv
    HAS_PYG = True
except ImportError:
    HAS_PYG = False
    PyGGATv2Conv = None


# ============================================================================
# Native PyTorch GATv2 Layer (How Attentive are Graph Attention Networks? ICLR 2022)
# Provides seamless standalone operation with identical API to torch_geometric.nn.GATv2Conv
# ============================================================================
class NativeGATv2Conv(nn.Module):
    def __init__(
        self,
        in_channels: int,
        out_channels: int,
        heads: int = 1,
        concat: bool = True,
        negative_slope: float = 0.2,
        dropout: float = 0.0,
        edge_dim: Optional[int] = None,
    ):
        super().__init__()
        self.in_channels = in_channels
        self.out_channels = out_channels
        self.heads = heads
        self.concat = concat
        self.negative_slope = negative_slope
        self.dropout = dropout
        self.edge_dim = edge_dim

        self.lin_l = nn.Linear(in_channels, heads * out_channels, bias=False)
        self.lin_r = nn.Linear(in_channels, heads * out_channels, bias=False)

        if edge_dim is not None:
            self.lin_edge = nn.Linear(edge_dim, heads * out_channels, bias=False)
        else:
            self.register_parameter("lin_edge", None)

        self.att = nn.Parameter(torch.Tensor(1, heads, out_channels))
        self.bias = nn.Parameter(torch.Tensor(heads * out_channels if concat else out_channels))
        self.reset_parameters()

    def reset_parameters(self):
        nn.init.xavier_uniform_(self.lin_l.weight)
        nn.init.xavier_uniform_(self.lin_r.weight)
        if self.lin_edge is not None:
            nn.init.xavier_uniform_(self.lin_edge.weight)
        nn.init.xavier_uniform_(self.att)
        nn.init.zeros_(self.bias)

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_attr: Optional[torch.Tensor] = None,
        return_attention_weights: bool = False,
    ) -> Tuple[torch.Tensor, Optional[Tuple[torch.Tensor, torch.Tensor]]]:
        num_nodes = x.size(0)
        num_edges = edge_index.size(1)

        # Handle empty edge graphs
        if num_edges == 0:
            out = self.lin_l(x) if self.concat else self.lin_l(x).view(num_nodes, self.heads, self.out_channels).mean(dim=1)
            out = out + self.bias
            att_weights = (edge_index, torch.empty((0, self.heads), device=x.device)) if return_attention_weights else None
            return (out, att_weights) if return_attention_weights else out

        h_l = self.lin_l(x).view(-1, self.heads, self.out_channels)
        h_r = self.lin_r(x).view(-1, self.heads, self.out_channels)

        src, dst = edge_index[0], edge_index[1]
        score = h_l[src] + h_r[dst]

        if edge_attr is not None and self.lin_edge is not None:
            h_e = self.lin_edge(edge_attr).view(-1, self.heads, self.out_channels)
            score = score + h_e

        score = F.leaky_relu(score, negative_slope=self.negative_slope)
        alpha = (score * self.att).sum(dim=-1)  # [E, heads]

        # Softmax over incoming edges per destination node
        alpha_exp = torch.exp(alpha - alpha.max(dim=0, keepdim=True)[0])
        denom = torch.zeros(num_nodes, self.heads, device=x.device).scatter_add_(0, dst.unsqueeze(-1).expand(-1, self.heads), alpha_exp)
        denom = denom[dst] + 1e-12
        alpha_norm = alpha_exp / denom

        if self.dropout > 0 and self.training:
            alpha_norm = F.dropout(alpha_norm, p=self.dropout, training=True)

        # Message passing: aggregate features
        msg = h_l[src] * alpha_norm.unsqueeze(-1)  # [E, heads, out_channels]
        out = torch.zeros(num_nodes, self.heads, self.out_channels, device=x.device)
        out = out.scatter_add(0, dst.view(-1, 1, 1).expand(-1, self.heads, self.out_channels), msg)

        if self.concat:
            out = out.view(num_nodes, self.heads * self.out_channels)
        else:
            out = out.mean(dim=1)

        out = out + self.bias

        if return_attention_weights:
            return out, (edge_index, alpha_norm)
        return out


# ============================================================================
# Provenance GATv2 Autoencoder & Edge Anomaly Scorer
# ============================================================================
class ProvenanceGATv2AutoEncoder(nn.Module):
    """
    Spatio-Temporal Graph Neural Network Autoencoder.
    Computes contextual node embeddings via multi-head GATv2 layers with edge features,
    reconstructs normal causal transitions, and scores edge-level anomaly probabilities (0.0 to 1.0).
    """

    def __init__(
        self,
        in_channels: int = 16,
        hidden_channels: int = 32,
        latent_channels: int = 16,
        edge_dim: int = 8,
        heads: int = 4,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.in_channels = in_channels
        self.edge_dim = edge_dim
        self.latent_channels = latent_channels

        # GATv2 Layer 1: [N, 16] -> [N, hidden_channels * heads]
        self.conv1 = NativeGATv2Conv(
            in_channels=in_channels,
            out_channels=hidden_channels,
            heads=heads,
            concat=True,
            edge_dim=edge_dim,
            dropout=dropout,
        )

        # GATv2 Layer 2: [N, hidden_channels * heads] -> [N, latent_channels]
        self.conv2 = NativeGATv2Conv(
            in_channels=hidden_channels * heads,
            out_channels=latent_channels,
            heads=1,
            concat=False,
            edge_dim=edge_dim,
            dropout=dropout,
        )

        # Decoder 1: Node Feature Reconstruction Head
        self.node_decoder = nn.Sequential(
            nn.Linear(latent_channels, hidden_channels),
            nn.LeakyReLU(0.2),
            nn.Linear(hidden_channels, in_channels),
        )

        # Decoder 2: Edge-level Malicious Transition Classifier
        # Input features: [z_u, z_v, z_u * z_v, |z_u - z_v|, edge_attr]
        edge_mlp_in = (latent_channels * 4) + edge_dim
        self.edge_anomaly_head = nn.Sequential(
            nn.Linear(edge_mlp_in, 64),
            nn.LeakyReLU(0.2),
            nn.Dropout(dropout),
            nn.Linear(64, 32),
            nn.LeakyReLU(0.2),
            nn.Linear(32, 1),
            nn.Sigmoid(),  # Output calibrated anomaly score between 0.0 and 1.0
        )

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_attr: Optional[torch.Tensor] = None,
        return_attention_weights: bool = True,
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, Optional[Tuple[torch.Tensor, torch.Tensor]]]:
        """
        Forward pass.
        Returns:
            z: Latent node embeddings [N, latent_channels]
            node_recon: Reconstructed node features [N, in_channels]
            edge_scores: Malicious causal anomaly score [E, 1]
            attention_weights: (edge_index, alpha [E, heads])
        """
        if edge_attr is None:
            edge_attr = torch.zeros((edge_index.size(1), self.edge_dim), device=x.device)

        # Layer 1
        h1 = self.conv1(x, edge_index, edge_attr=edge_attr, return_attention_weights=False)
        h1 = F.elu(h1)

        # Layer 2 with attention weights
        if return_attention_weights:
            z, (edge_idx_ret, alpha) = self.conv2(
                h1, edge_index, edge_attr=edge_attr, return_attention_weights=True
            )
        else:
            z = self.conv2(h1, edge_index, edge_attr=edge_attr, return_attention_weights=False)
            edge_idx_ret, alpha = edge_index, None

        z = F.elu(z)

        # Node reconstruction
        node_recon = self.node_decoder(z)

        # Edge Anomaly Scoring
        num_edges = edge_index.size(1)
        if num_edges > 0:
            src, dst = edge_index[0], edge_index[1]
            z_u, z_v = z[src], z[dst]
            edge_repr = torch.cat(
                [
                    z_u,
                    z_v,
                    z_u * z_v,
                    torch.abs(z_u - z_v),
                    edge_attr,
                ],
                dim=-1,
            )
            edge_scores = self.edge_anomaly_head(edge_repr)
        else:
            edge_scores = torch.empty((0, 1), device=x.device)

        attention_tuple = (edge_idx_ret, alpha) if return_attention_weights else None
        return z, node_recon, edge_scores, attention_tuple

    @torch.no_grad()
    def score_subgraph(self, pyg_data: Any) -> Dict[str, Any]:
        """
        Inference routine for a sampled k-hop causal subgraph.
        Returns structured metrics and flagged edges for UI Cytoscape highlighting and LLM hot-patching.
        """
        self.eval()
        x = pyg_data.x
        edge_index = pyg_data.edge_index
        edge_attr = getattr(pyg_data, "edge_attr", None)
        node_names = getattr(pyg_data, "node_names", [])
        edge_metadata = getattr(pyg_data, "edge_metadata", [])

        z, node_recon, edge_scores, att = self.forward(
            x, edge_index, edge_attr=edge_attr, return_attention_weights=True
        )

        num_edges = edge_index.size(1)
        scores_list = edge_scores.squeeze(-1).tolist() if num_edges > 0 else []
        if isinstance(scores_list, float):
            scores_list = [scores_list]

        # Extract attention weights averaged across heads
        if att is not None and att[1] is not None and att[1].size(0) > 0:
            alpha_avg = att[1].mean(dim=-1).tolist()
        else:
            alpha_avg = [0.0] * num_edges

        # Map edge metrics back to causal graph
        evaluated_edges = []
        for i in range(num_edges):
            meta = edge_metadata[i] if i < len(edge_metadata) else {}
            score = scores_list[i] if i < len(scores_list) else 0.0
            weight = alpha_avg[i] if i < len(alpha_avg) else 0.0
            evaluated_edges.append(
                {
                    "src": meta.get("src", f"Node:{edge_index[0, i].item()}"),
                    "dst": meta.get("dst", f"Node:{edge_index[1, i].item()}"),
                    "syscall": meta.get("syscall_name", "syscall"),
                    "anomaly_score": round(float(score), 4),
                    "gat_attention_weight": round(float(weight), 4),
                }
            )

        # Sort edges by descending anomaly score & attention weight
        evaluated_edges.sort(key=lambda item: (item["anomaly_score"], item["gat_attention_weight"]), reverse=True)

        max_anomaly = max(scores_list) if scores_list else 0.0

        return {
            "subgraph_nodes_count": len(node_names),
            "subgraph_edges_count": num_edges,
            "max_edge_anomaly_score": round(float(max_anomaly), 4),
            "is_anomalous": bool(max_anomaly > 0.65),
            "trigger_node": getattr(pyg_data, "trigger_node", ""),
            "top_anomalous_edges": evaluated_edges[:5],
            "all_evaluated_edges": evaluated_edges,
            "latent_embeddings": z.cpu().numpy().tolist(),
        }
