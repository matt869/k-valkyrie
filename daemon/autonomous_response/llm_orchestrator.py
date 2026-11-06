"""
K-Valkyrie Autonomous Response LLM Orchestrator
Connects to local OpenAI-compatible / Ollama endpoints (deepseek-r1 / qwen2.5-coder)
to synthesize surgical containment rules and least-privilege Seccomp profiles.
"""

from __future__ import annotations
import json
import logging
import re
import time
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger("kv.autonomous_response")


SYSTEM_PROMPT = """You are the Autonomous Kernel Remediation Engine inside K-Valkyrie, a Ring-0 Linux runtime defense platform.
An anomalous execution subgraph has crossed our Graph Neural Network (GATv2) threshold, and the offending PID tree is currently frozen via `SIGSTOP` in kernel space.

Your task is to analyze the serialized eBPF Provenance Subgraph and GATv2 edge attention weights, identify the exact exploitation primitive, and output a valid, strictly formatted JSON response containing:
1. Mitre ATT&CK mapping and root-cause forensic summary.
2. A least-privilege Seccomp-BPF profile that blocks the malicious syscall chain while allowing the legitimate parent service to continue operating.
3. A surgical eBPF LSM C snippet to enforce inode/process-level quarantine if the attack attempts namespace escape or memory injection.

Strict Output Rules:
- Respond ONLY with a valid JSON object matching the requested schema.
- Base your decision strictly on the causal edges with the highest gat_attention_weight.
- Never kill the parent daemon if surgical syscall blocking is sufficient.

Required JSON Schema:
{
  "incident_classification": {
    "attack_type": "FILELESS_MEMFD_EXEC | PTRACE_INJECTION | CONTAINER_ESCAPE | LOTL_RCE",
    "mitre_techniques": ["T1620", "T1055.008"],
    "confidence": 0.98,
    "root_cause_summary": "Concise 2-sentence explanation of the causal syscall chain."
  },
  "kernel_enforcement_decision": {
    "quarantine_action": "KILL_SUBTREE | MAINTAIN_SIGSTOP | APPLY_SECCOMP_AND_RESUME",
    "target_pids_to_terminate": [4192],
    "parent_pid_to_preserve": 1042
  },
  "seccomp_bpf_patch": {
    "defaultAction": "SCMP_ACT_ALLOW",
    "architectures": ["SCMP_ARCH_X86_64"],
    "syscalls": [
      {
        "names": ["memfd_create", "execveat", "ptrace"],
        "action": "SCMP_ACT_ERRNO",
        "errnoRet": 1
      }
    ]
  },
  "ebpf_lsm_rule_c": "SEC(\\"lsm/bprm_check_security\\") int BPF_PROG(block_anon_elf, struct linux_binprm *bprm) { return -1; }"
}
"""


class LLMOrchestrator:
    """
    Interfaces with local LLM (Ollama / vLLM) with validation and automatic fallback.
    """

    def __init__(
        self,
        endpoint: str = "http://localhost:11434/v1/chat/completions",
        model: str = "qwen2.5-coder",
        timeout_seconds: int = 20,
        max_retries: int = 2,
    ):
        self.endpoint = endpoint
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

    def generate_remediation(self, prompt: str) -> Dict[str, Any]:
        """Sends prompt to local LLM and returns parsed JSON remediation plan."""
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
            "max_tokens": 1500,
        }

        for attempt in range(self.max_retries + 1):
            try:
                response = requests.post(
                    self.endpoint,
                    json=payload,
                    timeout=self.timeout_seconds,
                    headers={"Content-Type": "application/json"},
                )
                if response.status_code == 200:
                    raw_content = response.json()["choices"][0]["message"]["content"]
                    parsed = self._extract_json(raw_content)
                    if parsed and self._validate_schema(parsed):
                        return parsed
            except Exception as e:
                logger.warning(f"LLM API request failed (attempt {attempt + 1}): {e}")
                time.sleep(1.0 * (attempt + 1))

        # Fallback to local heuristic rule generator if local LLM is offline or invalid
        return self._generate_fallback_remediation(prompt)

    def _extract_json(self, text: str) -> Optional[Dict[str, Any]]:
        """Strips markdown code fences and parses JSON."""
        clean = text.strip()
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", clean, re.DOTALL)
        if match:
            clean = match.group(1)
        try:
            return json.loads(clean)
        except json.JSONDecodeError:
            return None

    def _validate_schema(self, data: Dict[str, Any]) -> bool:
        """Validates that necessary top-level keys exist."""
        required_keys = [
            "incident_classification",
            "kernel_enforcement_decision",
            "seccomp_bpf_patch",
            "ebpf_lsm_rule_c",
        ]
        return all(k in data for k in required_keys)

    def _generate_fallback_remediation(self, prompt: str) -> Dict[str, Any]:
        """Deterministic safety fallback when local LLM is unreachable."""
        target_pid = 4192
        if "Process:" in prompt:
            m = re.search(r"Process:(\d+)", prompt)
            if m:
                target_pid = int(m.group(1))

        return {
            "incident_classification": {
                "attack_type": "FILELESS_MEMFD_EXEC",
                "mitre_techniques": ["T1620", "T1055.008"],
                "confidence": 0.95,
                "root_cause_summary": "Autonomous detection of in-memory anonymous memfd execution chain.",
            },
            "kernel_enforcement_decision": {
                "quarantine_action": "APPLY_SECCOMP_AND_RESUME",
                "target_pids_to_terminate": [target_pid],
                "parent_pid_to_preserve": 1,
            },
            "seccomp_bpf_patch": {
                "defaultAction": "SCMP_ACT_ALLOW",
                "architectures": ["SCMP_ARCH_X86_64"],
                "syscalls": [
                    {
                        "names": ["memfd_create", "execveat", "ptrace"],
                        "action": "SCMP_ACT_ERRNO",
                        "errnoRet": 1,
                    }
                ],
            },
            "ebpf_lsm_rule_c": (
                'SEC("lsm/bprm_check_security")\n'
                "int BPF_PROG(block_anon_elf, struct linux_binprm *bprm) {\n"
                "    return -1; /* -EPERM */\n"
                "}"
            ),
        }
