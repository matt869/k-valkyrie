"""
K-Valkyrie Edge Anomaly Classifier
Predicts probability of malicious causal transitions between provenance graph entities.
"""

from __future__ import annotations
import os
from typing import Any, Dict, List, Optional, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F


class EdgeClassifier(nn.Module):
    """
    Multi-layer Perceptron for classifying causal edge transitions as benign or malicious.
    Inputs:
        z_src: Latent embedding of source entity [N, D]
        z_dst: Latent embedding of destination entity [N, D]
        edge_attr: Syscall attributes and temporal features [N, E]
    """

    def __init__(
        self,
        node_embed_dim: int = 16,
        edge_feat_dim: int = 8,
        hidden_dim: int = 64,
        dropout: float = 0.15,
    ):
        super().__init__()
        self.node_embed_dim = node_embed_dim
        self.edge_feat_dim = edge_feat_dim

        # Input dimension: [z_u, z_v, z_u * z_v, |z_u - z_v|, edge_attr]
        in_dim = (node_embed_dim * 4) + edge_feat_dim

        self.net = nn.Sequential(
            nn.Linear(in_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.LeakyReLU(0.2),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.BatchNorm1d(hidden_dim // 2),
            nn.LeakyReLU(0.2),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, 1),
            nn.Sigmoid(),
        )

    def forward(
        self,
        z_src: torch.Tensor,
        z_dst: torch.Tensor,
        edge_attr: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        if edge_attr is None:
            edge_attr = torch.zeros((z_src.size(0), self.edge_feat_dim), device=z_src.device)

        hadamard = z_src * z_dst
        diff = torch.abs(z_src - z_dst)
        combined = torch.cat([z_src, z_dst, hadamard, diff, edge_attr], dim=-1)
        return self.net(combined)

    def predict_proba(
        self,
        z_src: torch.Tensor,
        z_dst: torch.Tensor,
        edge_attr: Optional[torch.Tensor] = None,
    ) -> List[float]:
        self.eval()
        with torch.no_grad():
            preds = self.forward(z_src, z_dst, edge_attr)
            return preds.squeeze(-1).tolist()


def train_epoch(
    model: EdgeClassifier,
    dataloader: Any,
    optimizer: torch.optim.Optimizer,
    criterion: nn.Module,
    device: torch.device,
) -> float:
    """Trains edge classifier for one epoch and returns average loss."""
    model.train()
    total_loss = 0.0
    total_batches = 0

    for batch in dataloader:
        z_src = batch["z_src"].to(device)
        z_dst = batch["z_dst"].to(device)
        edge_attr = batch.get("edge_attr", None)
        if edge_attr is not None:
            edge_attr = edge_attr.to(device)
        labels = batch["label"].to(device).float().unsqueeze(-1)

        optimizer.zero_grad()
        preds = model(z_src, z_dst, edge_attr)
        loss = criterion(preds, labels)
        loss.backward()
        optimizer.step()

        total_loss += loss.item()
        total_batches += 1

    return total_loss / max(total_batches, 1)


def evaluate(
    model: EdgeClassifier,
    dataloader: Any,
    criterion: nn.Module,
    device: torch.device,
) -> Tuple[float, float]:
    """Evaluates edge classifier and returns (avg_loss, accuracy)."""
    model.eval()
    total_loss = 0.0
    correct = 0
    total = 0

    with torch.no_grad():
        for batch in dataloader:
            z_src = batch["z_src"].to(device)
            z_dst = batch["z_dst"].to(device)
            edge_attr = batch.get("edge_attr", None)
            if edge_attr is not None:
                edge_attr = edge_attr.to(device)
            labels = batch["label"].to(device).float().unsqueeze(-1)

            preds = model(z_src, z_dst, edge_attr)
            loss = criterion(preds, labels)
            total_loss += loss.item()

            binary_preds = (preds >= 0.5).float()
            correct += (binary_preds == labels).sum().item()
            total += labels.size(0)

    avg_loss = total_loss / max(len(dataloader), 1)
    accuracy = correct / max(total, 1)
    return avg_loss, accuracy
