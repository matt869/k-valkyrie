"""
K-Valkyrie eBPF LSM Hot-Compiler & Dynamic Rule Loader
Validates, compiles, and dynamically loads surgical eBPF LSM containment bytecode
synthesized by the local LLM engine.
"""

from __future__ import annotations
import logging
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("kv.lsm_compiler")

FORBIDDEN_PATTERNS = [
    r"bpf_probe_write_user",
    r"bpf_override_return",
    r"system\(",
    r"popen\(",
    r"/dev/kmem",
    r"/dev/mem",
]


class LSMHotCompiler:
    """Safely validates and compiles LLM-generated eBPF LSM C snippets into BPF bytecode."""

    def __init__(
        self,
        headers_dir: str = "ebpf_probes/headers",
        clang_binary: str = "clang",
    ):
        self.headers_dir = headers_dir
        self.clang_binary = clang_binary

    def validate_c_snippet(self, c_code: str) -> Tuple[bool, List[str]]:
        """Static analysis of generated C code before kernel verification."""
        errors: List[str] = []

        if not c_code or len(c_code.strip()) == 0:
            return False, ["C code snippet is empty"]

        # Check for forbidden dangerous helpers
        for pat in FORBIDDEN_PATTERNS:
            if re.search(pat, c_code):
                errors.append(f"Security violation: code contains forbidden pattern '{pat}'")

        # Must have SEC("lsm/...") annotation
        if not re.search(r'SEC\s*\(\s*"lsm/[a-zA-Z0-9_]+"\s*\)', c_code):
            errors.append("Missing required SEC(\"lsm/...\") LSM hook annotation")

        # Length safety limit
        if len(c_code) > 100_000:
            errors.append("C snippet exceeds maximum allowable size (100KB)")

        return len(errors) == 0, errors

    def compile_rule(self, c_code: str, output_obj_path: Optional[str] = None) -> Tuple[bool, str]:
        """Compiles validated C snippet to an ELF BPF object file."""
        is_valid, errors = self.validate_c_snippet(c_code)
        if not is_valid:
            return False, f"Validation failed: {'; '.join(errors)}"

        # Non-Linux mock compilation
        if sys.platform != "linux":
            logger.info("[SIMULATION] Simulated eBPF LSM hot-compilation succeeded.")
            return True, "Simulated BPF bytecode ready"

        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as tf:
            # Wrap snippet with necessary headers if not present
            full_code = c_code
            if "vmlinux.h" not in c_code:
                full_code = (
                    '#include "headers/vmlinux.h"\n'
                    "#include <bpf/bpf_helpers.h>\n"
                    "#include <bpf/bpf_tracing.h>\n"
                    "#include <bpf/bpf_core_read.h>\n"
                    'char LICENSE[] SEC("license") = "Dual BSD/GPL";\n\n'
                    + c_code
                )
            tf.write(full_code)
            temp_c_path = tf.name

        out_path = output_obj_path or temp_c_path.replace(".c", ".o")

        cmd = [
            self.clang_binary,
            "-g",
            "-O2",
            "-target",
            "bpf",
            "-D__TARGET_ARCH_x86",
            f"-I{self.headers_dir}",
            "-c",
            temp_c_path,
            "-o",
            out_path,
        ]

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if res.returncode == 0:
                logger.info(f"[+] eBPF LSM rule compiled: {out_path}")
                return True, out_path
            else:
                logger.error(f"[-] Clang compilation failed:\n{res.stderr}")
                return False, res.stderr
        except Exception as e:
            return False, str(e)
        finally:
            if os.path.exists(temp_c_path):
                os.unlink(temp_c_path)
