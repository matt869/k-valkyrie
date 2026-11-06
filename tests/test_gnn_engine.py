"""
Tests for K-Valkyrie GNN Autoencoder and Feature Embedder
"""

import sys
from pathlib import Path
import pytest
import torch

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from daemon.gnn_engine.models.tgn_autoencoder import ProvenanceGATv2AutoEncoder
from daemon.gnn_engine.models.edge_classifier import EdgeClassifier
from daemon.gnn_engine.features.node_embedder import NodeEmbedder
from daemon.provenance_graph.graph_builder import PyGData


def test_node_embedder_dimensions():
    p_vec = NodeEmbedder.embed_process(1234, 100, 0, 0, 10, "evil_daemon")
    assert len(p_vec) == 16
    assert p_vec[0] == 1.0  # Process type
    assert p_vec[4] == 1.0  # Root UID

    f_vec = NodeEmbedder.embed_file("/etc/shadow", 9999, is_sensitive=True)
    assert len(f_vec) == 16
    assert f_vec[1] == 1.0  # File type
    assert f_vec[4] == 1.0  # Sensitive


def test_gatv2_autoencoder_forward():
    model = ProvenanceGATv2AutoEncoder(in_channels=16, hidden_channels=32, latent_channels=16, edge_dim=8)

    x = torch.randn(5, 16)
    edge_index = torch.tensor([[0, 1, 2, 3], [1, 2, 3, 4]], dtype=torch.long)
    edge_attr = torch.randn(4, 8)

    z, node_recon, edge_scores, att = model(x, edge_index, edge_attr=edge_attr, return_attention_weights=True)

    assert z.shape == (5, 16)
    assert node_recon.shape == (5, 16)
    assert edge_scores.shape == (4, 1)
    # Scores must be bounded in [0.0, 1.0] by sigmoid
    assert (edge_scores >= 0.0).all() and (edge_scores <= 1.0).all()
    assert att is not None
    assert att[0].shape == edge_index.shape


def test_edge_classifier_prediction():
    clf = EdgeClassifier(node_embed_dim=16, edge_feat_dim=8, hidden_dim=32)
    z_src = torch.randn(3, 16)
    z_dst = torch.randn(3, 16)
    edge_attr = torch.randn(3, 8)

    probs = clf.predict_proba(z_src, z_dst, edge_attr)
    assert len(probs) == 3
    for p in probs:
        assert 0.0 <= p <= 1.0
