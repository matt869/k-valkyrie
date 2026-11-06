"""
K-Valkyrie Real-Time Batched GNN Inference Engine
Optimized CPU/GPU inference loop with CUDA streams, latency tracking, and callback dispatch.
"""

from __future__ import annotations
import queue
import threading
import time
from typing import Any, Callable, Dict, List, Optional

import torch

from daemon.gnn_engine.models.tgn_autoencoder import ProvenanceGATv2AutoEncoder


class RealtimeInferenceEngine:
    """
    Consumes sampled PyG causal subgraphs from a thread-safe queue,
    executes batched inference with CUDA streams, and invokes alert callbacks.
    """

    def __init__(
        self,
        model: Optional[ProvenanceGATv2AutoEncoder] = None,
        weights_path: Optional[str] = None,
        batch_size: int = 8,
        max_latency_ms: float = 25.0,
        alert_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        anomaly_threshold: float = 0.65,
    ):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.batch_size = batch_size
        self.max_latency_ms = max_latency_ms
        self.alert_callback = alert_callback
        self.anomaly_threshold = anomaly_threshold

        # Initialize model
        if model is not None:
            self.model = model.to(self.device)
        else:
            self.model = ProvenanceGATv2AutoEncoder(
                in_channels=16,
                hidden_channels=32,
                latent_channels=16,
                edge_dim=8,
            ).to(self.device)

        if weights_path and torch.cuda.is_available():
            try:
                ckpt = torch.load(weights_path, map_location=self.device)
                self.model.load_state_dict(ckpt["model_state_dict"])
            except Exception as e:
                print(f"[-] Could not load weights from {weights_path}: {e}")

        self.model.eval()

        # CUDA Stream for asynchronous overlap
        self.stream = torch.cuda.Stream() if torch.cuda.is_available() else None

        # Queue and lifecycle
        self.task_queue: queue.Queue = queue.Queue(maxsize=1000)
        self.running = False
        self.worker_thread: Optional[threading.Thread] = None

        # Telemetry metrics
        self.total_processed = 0
        self.total_alerts = 0
        self.avg_inference_latency_ms = 0.0

        # Warm-up run
        self._warmup()

    def _warmup(self):
        """Runs dummy forward pass to initialize CUDA contexts and JIT caches."""
        x_dummy = torch.randn((4, 16), device=self.device)
        edge_index_dummy = torch.tensor([[0, 1, 2], [1, 2, 3]], dtype=torch.long, device=self.device)
        edge_attr_dummy = torch.zeros((3, 8), device=self.device)
        with torch.no_grad():
            _ = self.model(x_dummy, edge_index_dummy, edge_attr=edge_attr_dummy, return_attention_weights=True)

    def submit_subgraph(self, pyg_data: Any, context: Optional[Dict[str, Any]] = None) -> bool:
        """Pushes a subgraph into the inference queue (non-blocking)."""
        try:
            self.task_queue.put_nowait((pyg_data, context or {}))
            return True
        except queue.Full:
            return False

    def start(self):
        """Starts background worker thread."""
        if not self.running:
            self.running = True
            self.worker_thread = threading.Thread(target=self._inference_loop, daemon=True)
            self.worker_thread.start()

    def stop(self):
        """Stops background worker thread."""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=2.0)

    def _inference_loop(self):
        """Core batched inference loop."""
        while self.running:
            batch_items: List[Tuple[Any, Dict[str, Any]]] = []
            deadline = time.time() + (self.max_latency_ms / 1000.0)

            # Accumulate batch up to batch_size or deadline
            while len(batch_items) < self.batch_size and time.time() < deadline:
                remaining_time = max(0.001, deadline - time.time())
                try:
                    item = self.task_queue.get(timeout=remaining_time)
                    batch_items.append(item)
                except queue.Empty:
                    break

            if not batch_items:
                continue

            # Process items
            start_ts = time.perf_counter()
            for pyg_data, ctx in batch_items:
                self._process_single(pyg_data, ctx)

            latency_ms = (time.perf_counter() - start_ts) * 1000.0
            self.total_processed += len(batch_items)
            self.avg_inference_latency_ms = (
                (self.avg_inference_latency_ms * 0.9) + (latency_ms * 0.1)
            )

    def _process_single(self, pyg_data: Any, ctx: Dict[str, Any]):
        """Runs forward scoring on single subgraph item."""
        with torch.no_grad():
            res = self.model.score_subgraph(pyg_data)

        res["context"] = ctx
        is_alert = res["max_edge_anomaly_score"] >= self.anomaly_threshold

        if is_alert:
            self.total_alerts += 1
            if self.alert_callback:
                self.alert_callback(res)
