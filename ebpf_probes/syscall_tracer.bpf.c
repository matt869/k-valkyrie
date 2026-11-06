/*
 * K-Valkyrie Ring-0 eBPF Threat Detection & Autonomous Containment Engine
 * File: ebpf_probes/syscall_tracer.bpf.c
 *
 * Hooks:
 *  - tp/syscalls/sys_enter_execve       : Process execution tracking
 *  - tp/syscalls/sys_enter_memfd_create : Fileless anonymous ELF execution tracking
 *  - tp/syscalls/sys_enter_ptrace       : Process injection / hollowing tracking
 *  - lsm/bprm_check_security            : Execution integrity & quarantine enforcement
 *  - lsm/file_open                      : Inode access quarantine enforcement
 */

#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "headers/common_events.h"

#define EPERM 1
#define SIGSTOP 19

/*
 * Hash map containing PIDs targeted for quarantine / containment.
 * Key: __u32 PID
 * Value: __u8 quarantine_action (e.g. QUARANTINE_ACTION_SIGSTOP)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u8);
} quarantined_pids SEC(".maps");

/*
 * High-throughput BPF Ring Buffer for exporting structured telemetry events
 * to the userspace provenance graph ingestion daemon.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024); /* 16 MB ring buffer */
} events_ringbuf SEC(".maps");

/*
 * Helper: Extract Parent PID using CO-RE task struct traversal
 */
static __always_inline __u32 get_ppid(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;
    return BPF_CORE_READ(task, real_parent, tgid);
}

/*
 * Helper: Evaluate if process or its parent PID is flagged in quarantined_pids.
 * If quarantined, signal SIGSTOP to immediately freeze process tree and return -EPERM.
 */
static __always_inline int enforce_quarantine_check(__u32 pid, __u32 ppid, __u32 event_id, __u64 inode)
{
    __u8 *action = bpf_map_lookup_elem(&quarantined_pids, &pid);
    if (!action && ppid != 0) {
        action = bpf_map_lookup_elem(&quarantined_pids, &ppid);
    }

    if (action && *action >= QUARANTINE_ACTION_SIGSTOP) {
        /* Freeze offending thread/process tree immediately in Ring-0 */
        bpf_send_signal(SIGSTOP);

        /* Emit containment telemetry event */
        struct syscall_event_t *event = bpf_ringbuf_reserve(&events_ringbuf, sizeof(*event), 0);
        if (event) {
            __u64 uid_gid = bpf_get_current_uid_gid();
            event->timestamp_ns = bpf_ktime_get_ns();
            event->cgroup_id    = bpf_get_current_cgroup_id();
            event->inode        = inode;
            event->pid          = pid;
            event->ppid         = ppid;
            event->uid          = (__u32)uid_gid;
            event->gid          = (__u32)(uid_gid >> 32);
            event->syscall_id   = event_id;
            event->target_pid   = 0;
            event->fd_flags     = 0;
            event->action_taken = *action;

            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            bpf_probe_read_kernel_str(event->filename, sizeof(event->filename), "[BLOCKED_BY_QUARANTINE]");

            bpf_ringbuf_submit(event, 0);
        }
        return -EPERM;
    }

    return 0;
}

/*
 * Hook 1: tp/syscalls/sys_enter_execve
 * Tracks process execution attempts and argument boundaries
 */
SEC("tp/syscalls/sys_enter_execve")
int trace_sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid  = (__u32)(pid_tgid >> 32);
    __u32 ppid = get_ppid();

    struct syscall_event_t *event = bpf_ringbuf_reserve(&events_ringbuf, sizeof(*event), 0);
    if (!event)
        return 0;

    __u64 uid_gid = bpf_get_current_uid_gid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->cgroup_id    = bpf_get_current_cgroup_id();
    event->inode        = 0;
    event->pid          = pid;
    event->ppid         = ppid;
    event->uid          = (__u32)uid_gid;
    event->gid          = (__u32)(uid_gid >> 32);
    event->syscall_id   = VALKYRIE_SYS_EXECVE;
    event->target_pid   = 0;
    event->fd_flags     = 0;
    event->action_taken = QUARANTINE_ACTION_NONE;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    /* args[0] = const char *filename (userspace pointer) */
    const char *filename_ptr = (const char *)ctx->args[0];
    if (filename_ptr) {
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename_ptr);
    } else {
        event->filename[0] = '\0';
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/*
 * Hook 2: tp/syscalls/sys_enter_memfd_create
 * Detects fileless execution precursors (in-memory ELF staging)
 */
SEC("tp/syscalls/sys_enter_memfd_create")
int trace_sys_enter_memfd_create(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid  = (__u32)(pid_tgid >> 32);
    __u32 ppid = get_ppid();

    struct syscall_event_t *event = bpf_ringbuf_reserve(&events_ringbuf, sizeof(*event), 0);
    if (!event)
        return 0;

    __u64 uid_gid = bpf_get_current_uid_gid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->cgroup_id    = bpf_get_current_cgroup_id();
    event->inode        = 0;
    event->pid          = pid;
    event->ppid         = ppid;
    event->uid          = (__u32)uid_gid;
    event->gid          = (__u32)(uid_gid >> 32);
    event->syscall_id   = VALKYRIE_SYS_MEMFD_CREATE;
    event->target_pid   = 0;
    event->fd_flags     = (__u32)ctx->args[1]; /* unsigned int flags */
    event->action_taken = QUARANTINE_ACTION_NONE;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    /* args[0] = const char *uname (anonymous memory file name) */
    const char *uname_ptr = (const char *)ctx->args[0];
    if (uname_ptr) {
        bpf_probe_read_user_str(event->filename, sizeof(event->filename), uname_ptr);
    } else {
        event->filename[0] = '\0';
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/*
 * Hook 3: tp/syscalls/sys_enter_ptrace
 * Detects process injection, hollowing, and cross-PID code tampering
 */
SEC("tp/syscalls/sys_enter_ptrace")
int trace_sys_enter_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid  = (__u32)(pid_tgid >> 32);
    __u32 ppid = get_ppid();

    struct syscall_event_t *event = bpf_ringbuf_reserve(&events_ringbuf, sizeof(*event), 0);
    if (!event)
        return 0;

    __u64 uid_gid = bpf_get_current_uid_gid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->cgroup_id    = bpf_get_current_cgroup_id();
    event->inode        = 0;
    event->pid          = pid;
    event->ppid         = ppid;
    event->uid          = (__u32)uid_gid;
    event->gid          = (__u32)(uid_gid >> 32);
    event->syscall_id   = VALKYRIE_SYS_PTRACE;
    event->target_pid   = (__u32)ctx->args[1]; /* pid_t pid (target process) */
    event->fd_flags     = (__u32)ctx->args[0]; /* long request (PTRACE_ATTACH, PTRACE_POKETEXT, etc.) */
    event->action_taken = QUARANTINE_ACTION_NONE;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->filename[0] = '\0';

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/*
 * Hook 4: LSM bprm_check_security
 * Invoked during execve() binary validation before switching execution contexts.
 * Enforces zero-tolerance quarantine on marked PIDs/PPIDs and extracts target inode.
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(restrict_bprm, struct linux_binprm *bprm)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid  = (__u32)(pid_tgid >> 32);
    __u32 ppid = get_ppid();

    __u64 inode_num = 0;
    if (bprm && bprm->file) {
        inode_num = BPF_CORE_READ(bprm, file, f_inode, i_ino);
    }

    /* Check and immediately freeze + reject if quarantined */
    int ret = enforce_quarantine_check(pid, ppid, VALKYRIE_LSM_BPRM_CHECK, inode_num);
    if (ret != 0) {
        return ret; /* -EPERM */
    }

    return 0;
}

/*
 * Hook 5: LSM file_open
 * Enforces file-level confinement; blocks file access and freezes quarantined processes.
 */
SEC("lsm/file_open")
int BPF_PROG(restrict_file_open, struct file *file)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid  = (__u32)(pid_tgid >> 32);
    __u32 ppid = get_ppid();

    __u64 inode_num = 0;
    if (file) {
        inode_num = BPF_CORE_READ(file, f_inode, i_ino);
    }

    int ret = enforce_quarantine_check(pid, ppid, VALKYRIE_LSM_FILE_OPEN, inode_num);
    if (ret != 0) {
        return ret; /* -EPERM */
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
