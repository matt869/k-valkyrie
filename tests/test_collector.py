"""
Tests for K-Valkyrie Telemetry Collectors and BPF Map Controllers
"""

import sys
from pathlib import Path
import pytest

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from daemon.collector.map_controller import MapController
from daemon.collector.container_enricher import ContainerEnricher
from daemon.collector.ringbuf_consumer import RingBufConsumer


def test_map_controller_quarantine_crud():
    ctrl = MapController()
    assert ctrl.add_quarantine(4192, 2) is True
    assert 4192 in ctrl.list_quarantined()

    assert ctrl.add_quarantine(9999, 3) is True
    assert 9999 in ctrl.list_quarantined()

    assert ctrl.remove_quarantine(4192) is True
    assert 4192 not in ctrl.list_quarantined()
    assert 9999 in ctrl.list_quarantined()


def test_container_enricher_fallback():
    enricher = ContainerEnricher()
    info = enricher.enrich(pid=1)
    assert hasattr(info, "container_id")
    assert hasattr(info, "k8s_namespace")


def test_ringbuf_consumer_initialization():
    consumer = RingBufConsumer(force_simulation=True)
    events_received = []

    def on_event(evt):
        events_received.append(evt)

    consumer.register_callback(on_event)
    assert consumer._simulation_mode is True
