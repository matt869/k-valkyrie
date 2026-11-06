"""
Tests for K-Valkyrie Autonomous Response & Local LLM Hot-Patching Modules
"""

import sys
from pathlib import Path
import pytest

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from daemon.autonomous_response.subgraph_to_prompt import SubgraphPromptTranslator
from daemon.autonomous_response.seccomp_synthesizer import SeccompSynthesizer
from daemon.autonomous_response.lsm_hot_compiler import LSMHotCompiler
from daemon.autonomous_response.llm_orchestrator import LLMOrchestrator


def test_prompt_translator_formatting():
    scored_subgraph = {
        "trigger_node": "Process:4192",
        "max_edge_anomaly_score": 0.8921,
        "subgraph_nodes_count": 5,
        "subgraph_edges_count": 4,
        "top_anomalous_edges": [
            {
                "src": "Process:4192",
                "dst": "MemFD:anon_payload",
                "syscall": "memfd_create",
                "anomaly_score": 0.8921,
                "gat_attention_weight": 0.9412,
            }
        ],
    }

    prompt = SubgraphPromptTranslator.format_prompt(scored_subgraph, {"uid": "0 (root)"})
    assert "Process:4192" in prompt
    assert "memfd_create" in prompt
    assert "0.8921" in prompt


def test_seccomp_synthesizer_validation():
    valid_patch = {
        "defaultAction": "SCMP_ACT_ALLOW",
        "architectures": ["SCMP_ARCH_X86_64"],
        "syscalls": [
            {
                "names": ["memfd_create", "execveat"],
                "action": "SCMP_ACT_ERRNO",
            }
        ],
    }
    is_valid, errors = SeccompSynthesizer.validate_profile(valid_patch)
    assert is_valid is True
    assert len(errors) == 0

    # Test rejecting critical syscall block (safety check)
    unsafe_patch = {
        "defaultAction": "SCMP_ACT_ALLOW",
        "architectures": ["SCMP_ARCH_X86_64"],
        "syscalls": [
            {
                "names": ["exit_group", "memfd_create"],
                "action": "SCMP_ACT_KILL",
            }
        ],
    }
    is_valid, errors = SeccompSynthesizer.validate_profile(unsafe_patch)
    assert is_valid is False
    assert any("exit_group" in e for e in errors)


def test_lsm_hot_compiler_validation():
    compiler = LSMHotCompiler()

    valid_c = 'SEC("lsm/bprm_check_security") int BPF_PROG(test_block) { return -1; }'
    is_valid, errors = compiler.validate_c_snippet(valid_c)
    assert is_valid is True

    # Test forbidden helper detection
    unsafe_c = 'SEC("lsm/bprm_check_security") int BPF_PROG(bad) { bpf_probe_write_user(); return 0; }'
    is_valid, errors = compiler.validate_c_snippet(unsafe_c)
    assert is_valid is False
    assert any("bpf_probe_write_user" in e for e in errors)


def test_llm_orchestrator_fallback():
    orch = LLMOrchestrator(endpoint="http://127.0.0.1:9999/v1")  # Intentionally offline
    plan = orch.generate_remediation("Trigger on Process:4192 calling memfd_create")

    assert "incident_classification" in plan
    assert "seccomp_bpf_patch" in plan
    assert "ebpf_lsm_rule_c" in plan
    assert 4192 in plan["kernel_enforcement_decision"]["target_pids_to_terminate"]
