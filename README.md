# K-Valkyrie: Ring-0 eBPF Runtime Threat Detection & GNN Containment Engine

**K-Valkyrie** is a Linux runtime security engine designed for real-time detection and autonomous kernel-level containment of sophisticated attack primitives:
- **Fileless In-Memory Execution:** `memfd_create` + `execveat`
- **Process Injection & Hollowing:** `ptrace` attach, peek/poke text
- **Living-off-the-Land (LotL) Exploitation:** anomalous parent-child execution chains and sensitive file access

---

## Architecture Overview

```
                      +---------------------------------------+
                      |       Ring-0 Kernel Space (eBPF)      |
                      |                                       |
                      |  [Tracepoints: execve, memfd, ptrace] |
                      |  [LSM: bprm_check_security, file_open]|
                      |  [XDP: line-rate C2 IP packet drop]   |
                      +-------------------+-------------------+
                                          |
                      events_ringbuf      |  quarantined_pids (BPF Hash Map)
                      (16MB Ring Buffer)  |  (SIGSTOP + -EPERM Freeze)
                                          v
+-------------------------------------------------------------------------------+
|                       Userspace Telemetry & ML Engine                         |
|                                                                               |
|  1. Ingestion Daemon          2. Provenance DAG         3. GATv2 Autoencoder  |
|  (daemon/main.py)    --->     (Temporal Sliding    ---> (Edge Anomaly Scores  |
|                                Window Graph)             & Attention Weights) |
+---------------------------------------+---------------------------------------+
                                        |
                                        v
                    +---------------------------------------+
                    |    Autonomous Remediation Decision    |
                    |  - Freeze process subtree via BPF map |
                    |  - Synthesize least-privilege Seccomp |
                    |  - Compile surgical eBPF LSM bytecode |
                    +---------------------------------------+
```

---

## File Structure

```text
k-valkyrie/
├── .gitignore
├── Makefile                         # Compiles eBPF C bytecode (clang/llvm) & starts services
├── docker-compose.yml               # Privileged container setup for kernel debugfs/BPF mounts
├── README.md
├── LICENSE                          # Apache License 2.0
├── SECURITY.md                      # Responsible disclosure & kernel privilege policy
├── CONTRIBUTING.md                  # Development workflow & code guidelines
│
├── .github/
│   └── workflows/ci.yml             # CI: pytest matrix, eBPF clang compile check, dashboard build
│
├── scripts/
│   ├── setup.sh                     # Host toolchain + virtualenv bootstrap (clang/llvm/libbpf)
│   └── run_demo.py                  # Interactive end-to-end attack→detect→contain walkthrough
│
├── tests/                           # Pytest suite (collector, provenance graph, GNN, response)
│
├── ebpf_probes/                     # Ring-0 Kernel Space C Programs
│   ├── headers/
│   │   ├── vmlinux.h                # CO-RE (Compile Once - Run Everywhere) kernel types
│   │   └── common_events.h          # Shared ring-buffer structs between C and Python/Rust
│   ├── syscall_tracer.bpf.c         # Hooks execve, memfd_create, ptrace, clone, mprotect
│   ├── lsm_enforcer.bpf.c           # eBPF LSM hooks (file_open, bprm_check_security, socket_connect)
│   └── xdp_net_guard.bpf.c          # XDP packet drop program for instant C2 IP quarantine
│
├── daemon/                          # Core Telemetry & Graph Ingestion Engine (Python + BCC/libbpf)
│   ├── requirements.txt
│   ├── main.py                      # Daemon entry point: loads eBPF bytecode & attaches hooks
│   ├── config.yaml                  # Thresholds, monitored namespaces, local LLM endpoints
│   │
│   ├── collector/
│   │   ├── ringbuf_consumer.py      # Polls eBPF ring buffers at high throughput
│   │   ├── container_enricher.py    # Maps cgroup_id & pid_ns to Docker/K8s container metadata
│   │   └── map_controller.py        # Writes blocked PIDs/Inodes back into kernel BPF maps
│   │
│   ├── provenance_graph/
│   │   ├── graph_builder.py         # Maintains sliding-window Temporal Directed Acyclic Graph
│   │   ├── entity_tracker.py        # Tracks Process, File, Socket, and Memory-FD node states
│   │   ├── subgraph_sampler.py      # Extracts k-hop causal neighborhoods around suspicious events
│   │   └── serializer.py            # Converts subgraphs to PyTorch Geometric Data objects
│   │
│   ├── gnn_engine/                  # Deep Learning Graph Inference (PyTorch Geometric)
│   │   ├── models/
│   │   │   ├── tgn_autoencoder.py   # Temporal Graph Network + GATv2 encoder/decoder
│   │   │   └── edge_classifier.py   # Predicts probability of malicious causal transitions
│   │   ├── features/
│   │   │   └── node_embedder.py     # Encodes cmdline, syscall flags, file paths, and entropy
│   │   ├── weights/                 # Trained .pt checkpoints (trained on DARPA TC / StreamSpot)
│   │   ├── train_pipeline.py        # Self-supervised training on benign system provenance graphs
│   │   └── realtime_infer.py        # Batched GPU inference loop with CUDA stream optimization
│   │
│   └── autonomous_response/         # Local LLM Exploit Analysis & Hot-Patch Generator
│       ├── llm_orchestrator.py      # Connects to local vLLM / Ollama API (deepseek-r1 / qwen2.5-coder)
│       ├── subgraph_to_prompt.py    # Translates anomalous provenance subgraphs into structured prompts
│       ├── seccomp_synthesizer.py   # Generates & validates JSON Seccomp-BPF profiles via LLM
│       └── lsm_hot_compiler.py      # Compiles LLM-generated eBPF LSM containment rules on the fly
│
├── exploit_lab/                     # Red-Team Verification & Attack Simulation Suite
│   ├── fileless_memfd_loader.py     # Simulates in-memory ELF execution via memfd_create
│   ├── ptrace_injector.c            # Simulates process hollowing into a benign daemon
│   ├── dirty_pipe_escape.sh         # Simulates container privilege escalation / namespace breakout
│   └── lotl_reverse_shell.sh        # Living-off-the-Land multi-stage bash/python execution chain
│
└── dashboard/                       # Real-Time Provenance Graph Visualizer (React + Vite + Cytoscape.js)
    ├── package.json
    ├── src/
    │   ├── components/
    │   │   ├── LiveProvenanceGraph.jsx  # Interactive force-directed syscall graph (Cytoscape/WebGL)
    │   │   ├── KernelKillSwitch.jsx     # Manual/Auto eBPF LSM process tree freeze controls
    │   │   ├── SubgraphAnomalyDiff.jsx  # Highlights specific GATv2 attention weights on edges
    │   │   └── SeccompPatchViewer.jsx   # Displays LLM-synthesized Seccomp/eBPF patch code
    │   └── services/
    │       └── websocket_stream.js      # Subscribes to real-time kernel alert telemetry
```

---

## Quickstart & Compilation

### 1. Compile eBPF Kernel Probes (Linux 5.15+)

Ensure `clang`, `llvm`, and `bpftool` are installed:
```bash
sudo apt-get update && sudo apt-get install -y \
    clang llvm libelf-dev libbpf-dev linux-tools-common \
    linux-tools-$(uname -r) build-essential
```

Compile all eBPF probes:
```bash
cd k-valkyrie
make
```

### 2. Run the Telemetry & GNN Daemon

Install Python dependencies:
```bash
pip install -r daemon/requirements.txt
```

Run the daemon pipeline:
```bash
python daemon/main.py --simulate
```

---

## Privileged Docker Deployment

Deploy inside a container with access to host kernel debugfs and BPF subsystems:
```bash
docker compose up --build
```

---

## Interactive Demo

Walk through a full attack → detection → autonomous containment scenario (no root or Linux kernel required — runs against the simulation path):
```bash
python scripts/run_demo.py
```

---

## Testing & Continuous Integration

The daemon and GNN engine are covered by a `pytest` suite that runs against the simulation fallbacks, so no eBPF kernel attachment is required:
```bash
pip install -r daemon/requirements.txt pytest
python -m pytest tests/ -v
```

The GitHub Actions pipeline (`.github/workflows/ci.yml`) runs on every push and pull request to `main`:
- **`python-tests`** — the pytest suite on Python 3.10 and 3.11.
- **`ebpf-verification`** — compiles all three eBPF probes with the Clang BPF target.
- **`dashboard-build`** — installs and builds the React/Vite dashboard.

---

## Security & Responsible Use

K-Valkyrie is a **defensive** runtime-security research project. The `exploit_lab/` directory contains attack *simulations* used solely to verify that the detection and containment engine behaves correctly; run them only against systems you own or are explicitly authorized to test. See [SECURITY.md](SECURITY.md) for the responsible-disclosure policy and the kernel-privilege/least-privilege design notes.

---

## License

Licensed under the **Apache License 2.0** — see [LICENSE](LICENSE). Contributions are welcome; please read [CONTRIBUTING.md](CONTRIBUTING.md) first.
