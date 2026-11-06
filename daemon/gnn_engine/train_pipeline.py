"""
K-Valkyrie GNN Training Pipeline
Self-supervised training on benign system provenance graphs using reconstruction
and contrastive temporal edge losses.
"""

from __future__ import annotations
import argparse
import os
import random
import sys
from pathlib import Path
from typing import List, Tuple, Dict, Any

import torch
import torch.nn as nn
import torch.optim as optim

BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE_DIR))

from daemon.gnn_engine.models.tgn_autoencoder import ProvenanceGATv2AutoEncoder
from daemon.provenance_graph.graph_builder import PyGData


def generate_synthetic_benign_subgraph(num_nodes: int = 15, edge_prob: float = 0.25) -> PyGData:
    """Generates synthetic benign OS execution graphs for baseline calibration."""
    # Node features: standard benign processes and files
    x = torch.zeros((num_nodes, 16), dtype=torch.float32)
    for i in range(num_nodes):
        if i % 3 == 0:
            x[i, 0] = 1.0  # Process
            x[i, 4] = 0.0  # Non-root
            x[i, 7] = random.uniform(0.1, 0.4)
        else:
            x[i, 1] = 1.0  # File
            x[i, 7] = random.uniform(0.1, 0.3)

    # Benign tree-like edges
    src_list: List[int] = []
    dst_list: List[int] = []
    attr_list: List[List[float]] = []

    for i in range(1, num_nodes):
        parent = random.randint(0, i - 1)
        src_list.append(parent)
        dst_list.append(i)
        edge_feat = [0.0] * 8
        edge_feat[0] = 1.0  # execve/read
        edge_feat[7] = 1.0
        attr_list.append(edge_feat)

    # Add random cross-edges
    for i in range(num_nodes):
        for j in range(num_nodes):
            if i != j and random.random() < edge_prob / 2.0:
                src_list.append(i)
                dst_list.append(j)
                edge_feat = [0.0] * 8
                edge_feat[4] = 1.0  # file_open
                edge_feat[7] = 0.8
                attr_list.append(edge_feat)

    edge_index = torch.tensor([src_list, dst_list], dtype=torch.long)
    edge_attr = torch.tensor(attr_list, dtype=torch.float32)

    return PyGData(
        x=x,
        edge_index=edge_index,
        edge_attr=edge_attr,
        node_names=[f"Node_{i}" for i in range(num_nodes)],
        edge_metadata=[],
    )


def augment_graph(
    x: torch.Tensor,
    edge_index: torch.Tensor,
    edge_attr: torch.Tensor,
    feat_mask_prob: float = 0.1,
    edge_drop_prob: float = 0.1,
) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
    """Applies random node feature masking and edge dropout."""
    # 1. Feature masking
    x_aug = x.clone()
    mask = torch.rand_like(x_aug) < feat_mask_prob
    x_aug[mask] = 0.0

    # 2. Edge dropout
    num_edges = edge_index.size(1)
    if num_edges > 2:
        keep_mask = torch.rand(num_edges) >= edge_drop_prob
        if keep_mask.sum() > 0:
            edge_index_aug = edge_index[:, keep_mask]
            edge_attr_aug = edge_attr[keep_mask]
            return x_aug, edge_index_aug, edge_attr_aug

    return x_aug, edge_index, edge_attr


def train_model(
    epochs: int = 50,
    lr: float = 0.005,
    save_dir: str = "daemon/gnn_engine/weights",
) -> str:
    """Trains GATv2 Autoencoder and saves checkpoint."""
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[*] Training on device: {device}")

    model = ProvenanceGATv2AutoEncoder(
        in_channels=16,
        hidden_channels=32,
        latent_channels=16,
        edge_dim=8,
        heads=4,
    ).to(device)

    optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    mse_loss = nn.MSELoss()

    Path(save_dir).mkdir(parents=True, exist_ok=True)
    checkpoint_path = os.path.join(save_dir, "gatv2_autoencoder_best.pt")

    print("[*] Generating benign training graphs...")
    graphs = [generate_synthetic_benign_subgraph(random.randint(10, 25)) for _ in range(60)]

    model.train()
    for epoch in range(1, epochs + 1):
        epoch_loss = 0.0
        random.shuffle(graphs)

        for g in graphs:
            x, edge_index, edge_attr = augment_graph(g.x, g.edge_index, g.edge_attr)
            x = x.to(device)
            edge_index = edge_index.to(device)
            edge_attr = edge_attr.to(device)

            optimizer.zero_grad()
            z, node_recon, edge_scores, _ = model(
                x, edge_index, edge_attr=edge_attr, return_attention_weights=False
            )

            # Node feature reconstruction loss
            loss_recon = mse_loss(node_recon, x)

            # Benign edge regularizer: edge anomaly scores should be near 0 for benign graphs
            loss_edge = edge_scores.mean() if edge_scores.size(0) > 0 else torch.tensor(0.0, device=device)

            total_loss = loss_recon + (0.5 * loss_edge)
            total_loss.backward()
            optimizer.step()

            epoch_loss += total_loss.item()

        avg_loss = epoch_loss / len(graphs)
        if epoch % 10 == 0 or epoch == 1:
            print(f"[Epoch {epoch:03d}/{epochs:03d}] Avg Loss: {avg_loss:.4f}")

    torch.save(
        {
            "model_state_dict": model.state_dict(),
            "in_channels": 16,
            "latent_channels": 16,
            "edge_dim": 8,
            "epoch": epochs,
            "loss": avg_loss,
        },
        checkpoint_path,
    )
    print(f"[+] Checkpoint saved to: {checkpoint_path}")
    return checkpoint_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--epochs", type=int, default=20)
    args = parser.parse_args()
    train_model(epochs=args.epochs)
