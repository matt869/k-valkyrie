# Security Policy

## Responsible Disclosure

The K-Valkyrie project develops Ring-0 kernel telemetry, eBPF LSM enforcement, and autonomous containment mechanisms. We take security vulnerabilities seriously.

If you discover a security vulnerability in K-Valkyrie (especially concerning Ring-0 stability, eBPF verifier bypasses, or denial-of-service vectors), please report it responsibly:

- **Email:** security@k-valkyrie.org (or open a private security advisory on GitHub).
- **PGP Key:** Available upon request.
- Please do **not** disclose the issue publicly until a mitigation or patch has been issued.

## Kernel Capabilities & Privileges

K-Valkyrie requires `CAP_SYS_ADMIN`, `CAP_BPF`, `CAP_PERFMON`, and `CAP_SYS_PTRACE` to load eBPF bytecode and manipulate BPF hash maps. The core philosophy of K-Valkyrie is **surgical least-privilege**:
- Telemetry probes only read process context via read-only BPF helpers (`bpf_probe_read_user_str`, `bpf_core_read`).
- Containment relies on standard kernel primitives: `bpf_send_signal(SIGSTOP)` and returning `-EPERM` from LSM hooks.
- Write operations to user memory (`bpf_probe_write_user`) are strictly prohibited in the codebase.
