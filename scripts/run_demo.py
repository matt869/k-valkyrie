#!/usr/bin/env python3
"""
K-Valkyrie Interactive Demonstration CLI
Simulates multi-stage attack scenarios (fileless memfd execution & ptrace injection),
runs real-time GATv2 inference, highlights high-attention causal paths,
and demonstrates automated kernel containment via SIGSTOP freeze.
"""

from __future__ import annotations
import os
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from daemon.provenance_graph.graph_builder import (
    ProvenanceGraphBuilder,
    VALKYRIE_SYS_EXECVE,
    VALKYRIE_SYS_MEMFD_CREATE,
    VALKYRIE_SYS_PTRACE,
)
from daemon.gnn_engine.models.tgn_autoencoder import ProvenanceGATv2AutoEncoder
from daemon.collector.map_controller import MapController
from daemon.autonomous_response.llm_orchestrator import LLMOrchestrator
from daemon.autonomous_response.subgraph_to_prompt import SubgraphPromptTranslator


def print_banner():
    banner = """
======================================================================
  _  __     __     __     _      _  __ __   __ _____   ___  ______ 
 | |/ /     \\ \\   / //\\  | |    | |/ /\\ \\ / /|  __ \\ |_ _||  ____|
 | ' / _____ \\ \\_/ //  \\ | |    | ' /  \\ V / | |__) | | | | |__   
 |  < |_____| \\   // /\\ \\| |    |  <    > <  |  _  /  | | |  __|  
 | . \\         | |/ ____ \\ |____| . \\  / . \\ | | \\ \\ _| |_| |____ 
 |_|\\_\\        |_/_/    \\_\\_____|_|\\_\\/_/ \\_\\|_|  \\_\\_____|______|
                                                                  
  [ Ring-0 eBPF Threat Detection & Autonomous GNN Kernel Containment ]
======================================================================
    """
    print(banner)


def main():
    print_banner()

    builder = ProvenanceGraphBuilder()
    model = ProvenanceGATv2AutoEncoder(in_channels=16, hidden_channels=32, latent_channels=16, edge_dim=8)
    map_ctrl = MapController()
    orchestrator = LLMOrchestrator()

    print("\033[1;33m[*] STEP 1: Ingesting benign system telemetry (bash -> git)...\033[0m")
    time.sleep(0.6)

    t0 = int(time.time_ns())
    benign_events = [
        {"timestamp_ns": t0, "pid": 1042, "ppid": 1, "uid": 1000, "gid": 1000, "syscall_id": VALKYRIE_SYS_EXECVE, "filename": "/bin/bash", "comm": "bash"},
        {"timestamp_ns": t0 + 5000, "pid": 2048, "ppid": 1042, "uid": 1000, "gid": 1000, "syscall_id": VALKYRIE_SYS_EXECVE, "filename": "/usr/bin/git", "comm": "git"},
    ]

    for b_evt in benign_events:
        is_hr, _, _ = builder.process_event(b_evt)
        print(f"    [eBPF RingBuf] PID {b_evt['pid']} ({b_evt['comm']}) -> High Risk: {is_hr}")

    print("\n\033[1;31m[*] STEP 2: Attacker executes fileless in-memory ELF staging...\033[0m")
    time.sleep(0.8)

    attack_evt = {
        "timestamp_ns": t0 + 20000,
        "pid": 4192,
        "ppid": 1042,
        "uid": 0,
        "gid": 0,
        "cgroup_id": 104,
        "syscall_id": VALKYRIE_SYS_MEMFD_CREATE,
        "filename": "anon_elf_loader",
        "comm": "python3",
    }

    is_hr, trig, pyg_data = builder.process_event(attack_evt)
    print(f"\033[1;31m    [TRIGGER DETECTED]\033[0m High-risk syscall on {trig} (memfd_create)")
    print(f"    [*] Extracting 3-hop causal subgraph: {pyg_data.x.size(0)} entities, {pyg_data.edge_index.size(1)} transitions")

    print("\n\033[1;35m[*] STEP 3: Spatio-Temporal GNN (GATv2) Multi-Head Attention Scoring...\033[0m")
    time.sleep(0.8)

    res = model.score_subgraph(pyg_data)
    print(f"    - Peak Edge Anomaly Score: \033[1;31m{res['max_edge_anomaly_score']:.4f}\033[0m")
    print("    - Ranked Malicious Transitions (Attention Weighted):")
    for e in res["top_anomalous_edges"]:
        print(f"      * {e['src']} -> {e['dst']} | Syscall: {e['syscall']} | Anomaly: {e['anomaly_score']} | Attention: {e['gat_attention_weight']}")

    print("\n\033[1;32m[*] STEP 4: Kernel-Level Autonomous Containment...\033[0m")
    time.sleep(0.8)

    map_ctrl.add_quarantine(4192, 2)
    print("    \033[1;32m[+] PID 4192 frozen via SIGSTOP signal.\033[0m")
    print("    [+] eBPF LSM bprm_check_security & file_open will reject future execution (-EPERM).")

    print("\n\033[1;34m[*] STEP 5: Local LLM Autonomous Hot-Patch Synthesis...\033[0m")
    time.sleep(0.8)

    prompt = SubgraphPromptTranslator.format_prompt(res, attack_evt)
    patch = orchestrator.generate_remediation(prompt)
    print(f"    - Incident Classification: {patch['incident_classification']['attack_type']} (Confidence: {patch['incident_classification']['confidence']})")
    print(f"    - Root Cause: {patch['incident_classification']['root_cause_summary']}")
    print(f"    - Synthesized Seccomp Profile: Blocking {patch['seccomp_bpf_patch']['syscalls'][0]['names']}")

    print("\n\033[1;32m======================================================================\033[0m")
    print("\033[1;32m[+] K-Valkyrie demo complete: Attack neutralized with surgical precision.\033[0m")
    print("\033[1;32m======================================================================\033[0m\n")


if __name__ == "__main__":
    main()
