# Contributing to K-Valkyrie

We welcome contributions to eBPF kernel probes, graph neural network architectures, and the real-time visualization dashboard!

## Development Workflow

1. **Fork & Clone:**
   ```bash
   git clone https://github.com/matt869/k-valkyrie.git
   cd k-valkyrie
   ```

2. **Run Environment Setup:**
   ```bash
   sudo ./scripts/setup.sh
   ```

3. **Running the Test Suite:**
   ```bash
   pytest tests/ -v
   ```

4. **Compiling eBPF Probes:**
   ```bash
   make
   ```

## Code Guidelines

- **eBPF C Code:**
  - Must compile cleanly with `clang -target bpf -Wall -Werror`.
  - Must use CO-RE relocations (`BPF_CORE_READ`) for kernel struct traversal.
  - Must satisfy the Linux kernel eBPF verifier (bounded loops, no out-of-bounds pointer arithmetic).
- **Python Daemon:**
  - Adhere to Python 3.10+ typing (`from __future__ import annotations`).
  - Provide fallback simulation paths for non-Linux developer environments.
- **Pull Requests:**
  - Ensure all 14 tests pass (`pytest tests/`).
  - Keep commits clear and descriptive.
