"""
Tests for K-Valkyrie Provenance Graph and Causal Subgraph Modules
"""

import sys
from pathlib import Path
import pytest
import torch

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from daemon.provenance_graph.graph_builder import (
    ProvenanceGraphBuilder,
    VALKYRIE_SYS_EXECVE,
    VALKYRIE_SYS_MEMFD_CREATE,
    VALKYRIE_SYS_PTRACE,
)
from daemon.provenance_graph.entity_tracker import EntityTracker, EntityType, EntityState
from daemon.provenance_graph.subgraph_sampler import SubgraphSampler
from daemon.provenance_graph.serializer import ProvenanceSerializer, SubgraphSerializer


def test_provenance_graph_builder_basic():
    builder = ProvenanceGraphBuilder()

    # Ingest benign spawn
    is_hr, trig, data = builder.process_event({
        "timestamp_ns": 1000,
        "pid": 100,
        "ppid": 1,
        "uid": 1000,
        "gid": 1000,
        "syscall_id": VALKYRIE_SYS_EXECVE,
        "filename": "/bin/bash",
        "comm": "bash",
    })
    assert is_hr is False
    assert builder.graph.has_node("Process:100")
    assert builder.graph.has_node("Process:1")
    assert builder.graph.has_node("File:/bin/bash")


def test_provenance_graph_high_risk_trigger():
    builder = ProvenanceGraphBuilder()

    # Memfd create trigger
    is_hr, trig, pyg_data = builder.process_event({
        "timestamp_ns": 2000,
        "pid": 500,
        "ppid": 100,
        "uid": 0,
        "gid": 0,
        "syscall_id": VALKYRIE_SYS_MEMFD_CREATE,
        "filename": "payload_anon",
        "comm": "python3",
    })
    assert is_hr is True
    assert trig == "Process:500"
    assert pyg_data is not None
    assert pyg_data.x.size(0) >= 2
    assert pyg_data.edge_index.size(0) == 2


def test_entity_tracker_lifecycle():
    tracker = EntityTracker()
    tracker.register("Process:42", EntityType.PROCESS, metadata={"comm": "nginx", "pid": 42})
    assert tracker.get_active() is not None
    assert tracker.get("Process:42") is not None

    tracker.update("Process:42", metadata={"comm": "nginx: worker"})
    assert tracker.get("Process:42").metadata["comm"] == "nginx: worker"

    tracker.terminate("Process:42")
    assert tracker.get("Process:42").state == EntityState.TERMINATED


def test_subgraph_serializer_roundtrip():
    builder = ProvenanceGraphBuilder()
    _, _, pyg_data = builder.process_event({
        "timestamp_ns": 3000,
        "pid": 777,
        "ppid": 1,
        "syscall_id": VALKYRIE_SYS_MEMFD_CREATE,
        "filename": "memfd_test",
    })

    serializer = ProvenanceSerializer()
    json_repr = serializer.pyg_to_json(pyg_data)
    assert "node_features" in json_repr or "x" in json_repr
    assert "edge_index" in json_repr

    reconstructed = serializer.deserialize_from_json(json_repr)
    assert reconstructed.x.shape == pyg_data.x.shape
    assert reconstructed.edge_index.shape == pyg_data.edge_index.shape
