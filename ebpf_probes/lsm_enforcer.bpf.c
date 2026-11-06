/*
 * K-Valkyrie Ring-0 eBPF LSM Enforcement Module
 * File: ebpf_probes/lsm_enforcer.bpf.c
 *
 * Dedicated security enforcement layer providing fine-grained, path-aware
 * access control for quarantined processes. This module operates independently
 * from the syscall tracer to allow granular LSM policy without impacting
 * tracing throughput.
 *
 * Hooks:
 *  - lsm/file_open          : Blocks sensitive path access & memfd execution
 *  - lsm/bprm_check_security: Denies execution from writable/tmp/anon paths
 *  - lsm/socket_connect     : Blocks outbound TCP to prevent C2 communication
 *
 * Compile: clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
 *          -I headers/ -c lsm_enforcer.bpf.c -o lsm_enforcer.bpf.o
 */

#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "headers/common_events.h"

/* ------------------------------------------------------------------ */
/*  Error codes                                                       */
/* ------------------------------------------------------------------ */
#define EPERM  1
#define EACCES 13
#define SIGSTOP 19

/* ------------------------------------------------------------------ */
/*  Event IDs unique to this enforcer module (extended from common)   */
/* ------------------------------------------------------------------ */
#define VALKYRIE_LSM_SOCKET_CONNECT 1003

/* ------------------------------------------------------------------ */
/*  Shared BPF Maps                                                   */
/* ------------------------------------------------------------------ */

/*
 * Hash map containing PIDs targeted for quarantine / containment.
 * Populated by userspace daemon or the syscall_tracer module.
 * Key:   __u32 PID
 * Value: __u8  quarantine_action
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u8);
} quarantined_pids SEC(".maps");

/*
 * High-throughput Ring Buffer for exporting structured telemetry events.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024); /* 16 MB */
} events_ringbuf SEC(".maps");

/*
 * LRU hash of known Command & Control IPv4 addresses.
 * Populated by the userspace threat-intelligence feed ingestion daemon.
 * Key:   __u32  IPv4 address (network byte order)
 * Value: __u8   flag (non-zero = blocked)
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, __u32);
    __type(value, __u8);
} blocked_c2_ips SEC(".maps");

/* ------------------------------------------------------------------ */
/*  Inline Helpers                                                    */
/* ------------------------------------------------------------------ */

/*
 * Extract Parent PID via CO-RE task struct traversal.
 */
static __always_inline __u32 get_ppid(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;
    return BPF_CORE_READ(task, real_parent, tgid);
}

/*
 * Check if PID or PPID is in the quarantine map.
 * Returns pointer to action value, or NULL if neither is quarantined.
 */
static __always_inline __u8 *lookup_quarantine(__u32 pid, __u32 ppid)
{
    __u8 *action = bpf_map_lookup_elem(&quarantined_pids, &pid);
    if (action)
        return action;
    if (ppid != 0) {
        action = bpf_map_lookup_elem(&quarantined_pids, &ppid);
        if (action)
            return action;
    }
    return (void *)0;
}

/*
 * Emit a telemetry event to the ring buffer for blocked actions.
 */
static __always_inline void emit_block_event(
    __u32 pid, __u32 ppid, __u32 event_id, __u64 inode,
    __u8 action_taken, const char *path_tag)
{
    struct syscall_event_t *event =
        bpf_ringbuf_reserve(&events_ringbuf, sizeof(*event), 0);
    if (!event)
        return;

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
    event->action_taken = action_taken;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_kernel_str(event->filename, sizeof(event->filename),
                              path_tag);
    bpf_ringbuf_submit(event, 0);
}

/*
 * Byte-by-byte prefix match helper for kernel d_name strings.
 * Returns 1 if `haystack` starts with the compile-time constant `needle`.
 * `needle_len` includes the NUL terminator from sizeof("...").
 */
static __always_inline int prefix_match(const char *haystack,
                                        const char *needle,
                                        int needle_len)
{
    /*
     * needle_len includes trailing NUL from sizeof("...").
     * Compare needle_len - 1 actual characters.
     */
    int cmp_len = needle_len - 1;

    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (i >= cmp_len)
            return 1;
        char h = 0;
        bpf_probe_read_kernel(&h, 1, haystack + i);
        if (h != needle[i])
            return 0;
    }
    return 1;
}

/*
 * Read the full path from a file's dentry into a stack buffer.
 * This walks dentry->d_name.name via CO-RE. Returns the name pointer
 * (kernel-space) for prefix comparison.
 */
static __always_inline const char *get_dentry_name(struct file *f)
{
    return BPF_CORE_READ(f, f_path.dentry, d_name.name);
}

/*
 * Read the full path from dentry chain into a stack buffer.
 * Captures up to PATH_MAX_LEN bytes from d_name.name for path matching.
 */
static __always_inline int read_file_path(struct file *f, char *buf, int buf_sz)
{
    const char *name = BPF_CORE_READ(f, f_path.dentry, d_name.name);
    if (!name)
        return -1;
    return bpf_probe_read_kernel_str(buf, buf_sz, name);
}

/*
 * Walk d_parent dentry chain to reconstruct a partial path for matching
 * against known sensitive directories (/tmp, /dev/shm, /etc, /proc, /var).
 * Fills `buf` with parent directory name for prefix checking.
 */
static __always_inline int read_parent_dentry_name(struct file *f, char *buf,
                                                   int buf_sz)
{
    const char *name = BPF_CORE_READ(f, f_path.dentry, d_parent, d_name.name);
    if (!name)
        return -1;
    return bpf_probe_read_kernel_str(buf, buf_sz, name);
}

static __always_inline int read_grandparent_dentry_name(struct file *f,
                                                        char *buf, int buf_sz)
{
    const char *name = BPF_CORE_READ(f, f_path.dentry, d_parent, d_parent,
                                     d_name.name);
    if (!name)
        return -1;
    return bpf_probe_read_kernel_str(buf, buf_sz, name);
}

/*
 * Check whether a file is on an anonymous filesystem (e.g. memfd / anon_inode).
 * We compare the superblock's s_magic against ANON_INODE_FS_MAGIC (0x09041934).
 */
#define ANON_INODE_FS_MAGIC 0x09041934UL

static __always_inline bool is_anon_inode(struct file *f)
{
    unsigned long magic = BPF_CORE_READ(f, f_inode, i_sb, s_magic);
    return magic == ANON_INODE_FS_MAGIC;
}

/* ------------------------------------------------------------------ */
/*  LSM Hook 1: lsm/file_open                                        */
/*                                                                    */
/*  Policy for quarantined PIDs:                                      */
/*   - Block access to /etc/shadow, /etc/passwd, /proc/kallsyms,     */
/*     /var/run/docker.sock                                           */
/*   - Block anonymous inode execution (memfd)                        */
/* ------------------------------------------------------------------ */
SEC("lsm/file_open")
int BPF_PROG(lsm_restrict_file_open, struct file *file)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid  = (__u32)(pid_tgid >> 32);
    __u32 ppid = get_ppid();

    __u8 *action = lookup_quarantine(pid, ppid);
    if (!action)
        return 0; /* Not quarantined – allow */

    __u8 act = *action;
    if (act < QUARANTINE_ACTION_LOG)
        return 0;

    __u64 inode_num = 0;
    if (file)
        inode_num = BPF_CORE_READ(file, f_inode, i_ino);

    /* --- Check anonymous inode (memfd) execution --- */
    if (file && is_anon_inode(file)) {
        if (act >= QUARANTINE_ACTION_SIGSTOP)
            bpf_send_signal(SIGSTOP);
        emit_block_event(pid, ppid, VALKYRIE_LSM_FILE_OPEN, inode_num,
                         act, "[BLOCKED_ANON_INODE_OPEN]");
        return -EPERM;
    }

    /* --- Read dentry name and parent names for path matching --- */
    char fname[64];
    char parent[32];
    char grandparent[32];

    __builtin_memset(fname, 0, sizeof(fname));
    __builtin_memset(parent, 0, sizeof(parent));
    __builtin_memset(grandparent, 0, sizeof(grandparent));

    if (!file)
        return 0;

    int fname_ret = read_file_path(file, fname, sizeof(fname));
    if (fname_ret < 0)
        return 0;

    read_parent_dentry_name(file, parent, sizeof(parent));
    read_grandparent_dentry_name(file, grandparent, sizeof(grandparent));

    /*
     * Match: /etc/shadow
     * dentry chain: grandparent="/", parent="etc", name="shadow"
     */
    if (fname[0] == 's' && fname[1] == 'h' && fname[2] == 'a' &&
        fname[3] == 'd' && fname[4] == 'o' && fname[5] == 'w' &&
        fname[6] == '\0' &&
        parent[0] == 'e' && parent[1] == 't' && parent[2] == 'c' &&
        parent[3] == '\0') {
        goto block_access;
    }

    /*
     * Match: /etc/passwd
     * dentry chain: parent="etc", name="passwd"
     */
    if (fname[0] == 'p' && fname[1] == 'a' && fname[2] == 's' &&
        fname[3] == 's' && fname[4] == 'w' && fname[5] == 'd' &&
        fname[6] == '\0' &&
        parent[0] == 'e' && parent[1] == 't' && parent[2] == 'c' &&
        parent[3] == '\0') {
        goto block_access;
    }

    /*
     * Match: /proc/kallsyms
     * dentry chain: parent="proc", name="kallsyms"
     */
    if (fname[0] == 'k' && fname[1] == 'a' && fname[2] == 'l' &&
        fname[3] == 'l' && fname[4] == 's' && fname[5] == 'y' &&
        fname[6] == 'm' && fname[7] == 's' && fname[8] == '\0' &&
        parent[0] == 'p' && parent[1] == 'r' && parent[2] == 'o' &&
        parent[3] == 'c' && parent[4] == '\0') {
        goto block_access;
    }

    /*
     * Match: /var/run/docker.sock
     * dentry chain: grandparent="var" OR parent="run", name="docker.sock"
     */
    if (fname[0] == 'd' && fname[1] == 'o' && fname[2] == 'c' &&
        fname[3] == 'k' && fname[4] == 'e' && fname[5] == 'r' &&
        fname[6] == '.' && fname[7] == 's' && fname[8] == 'o' &&
        fname[9] == 'c' && fname[10] == 'k' && fname[11] == '\0' &&
        parent[0] == 'r' && parent[1] == 'u' && parent[2] == 'n' &&
        parent[3] == '\0') {
        goto block_access;
    }

    return 0; /* No sensitive path match – allow */

block_access:
    if (act >= QUARANTINE_ACTION_SIGSTOP)
        bpf_send_signal(SIGSTOP);

    emit_block_event(pid, ppid, VALKYRIE_LSM_FILE_OPEN, inode_num,
                     act, fname);
    return -EPERM;
}

/* ------------------------------------------------------------------ */
/*  LSM Hook 2: lsm/bprm_check_security                              */
/*                                                                    */
/*  Denies execution of binaries from:                                */
/*   - /tmp  (writable world directory)                               */
/*   - /dev/shm (in-memory tmpfs – common staging)                    */
/*   - Anonymous inodes (memfd_create ELF-in-memory execution)        */
/* ------------------------------------------------------------------ */
SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_restrict_bprm, struct linux_binprm *bprm)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid  = (__u32)(pid_tgid >> 32);
    __u32 ppid = get_ppid();

    __u8 *action = lookup_quarantine(pid, ppid);
    if (!action)
        return 0;

    __u8 act = *action;
    if (act < QUARANTINE_ACTION_LOG)
        return 0;

    struct file *exe_file = BPF_CORE_READ(bprm, file);
    if (!exe_file)
        return 0;

    __u64 inode_num = BPF_CORE_READ(exe_file, f_inode, i_ino);

    /* --- Block anonymous inode / memfd execution --- */
    if (is_anon_inode(exe_file)) {
        if (act >= QUARANTINE_ACTION_SIGSTOP)
            bpf_send_signal(SIGSTOP);
        emit_block_event(pid, ppid, VALKYRIE_LSM_BPRM_CHECK, inode_num,
                         act, "[BLOCKED_MEMFD_EXEC]");
        return -EPERM;
    }

    /* --- Read dentry names for path checks --- */
    char fname[64];
    char parent[32];
    char grandparent[32];

    __builtin_memset(fname, 0, sizeof(fname));
    __builtin_memset(parent, 0, sizeof(parent));
    __builtin_memset(grandparent, 0, sizeof(grandparent));

    read_file_path(exe_file, fname, sizeof(fname));

    int pret = read_parent_dentry_name(exe_file, parent, sizeof(parent));
    if (pret < 0)
        return 0;

    read_grandparent_dentry_name(exe_file, grandparent, sizeof(grandparent));

    /*
     * Match: /tmp/...
     * parent="tmp" and grandparent="/" (root)
     */
    if (parent[0] == 't' && parent[1] == 'm' && parent[2] == 'p' &&
        parent[3] == '\0') {
        goto block_exec;
    }

    /*
     * Match subdirectories under /tmp (e.g. /tmp/foo/bar)
     * grandparent="tmp"
     */
    if (grandparent[0] == 't' && grandparent[1] == 'm' &&
        grandparent[2] == 'p' && grandparent[3] == '\0') {
        goto block_exec;
    }

    /*
     * Match: /dev/shm/...
     * parent="shm" and grandparent="dev"
     */
    if (parent[0] == 's' && parent[1] == 'h' && parent[2] == 'm' &&
        parent[3] == '\0' &&
        grandparent[0] == 'd' && grandparent[1] == 'e' &&
        grandparent[2] == 'v' && grandparent[3] == '\0') {
        goto block_exec;
    }

    return 0; /* Execution path not restricted – allow */

block_exec:
    if (act >= QUARANTINE_ACTION_SIGSTOP)
        bpf_send_signal(SIGSTOP);

    emit_block_event(pid, ppid, VALKYRIE_LSM_BPRM_CHECK, inode_num,
                     act, fname);
    return -EPERM;
}

/* ------------------------------------------------------------------ */
/*  LSM Hook 3: lsm/socket_connect                                   */
/*                                                                    */
/*  Blocks all outbound TCP connections (AF_INET / AF_INET6) for      */
/*  quarantined PIDs.                                                 */
/*  Additionally blocks connections to known C2 IPv4 addresses        */
/*  (from blocked_c2_ips) for ALL processes.                          */
/* ------------------------------------------------------------------ */
SEC("lsm/socket_connect")
int BPF_PROG(lsm_restrict_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen)
{
    if (!address)
        return 0;

    __u16 sa_family = 0;
    bpf_probe_read_kernel(&sa_family, sizeof(sa_family), &address->sa_family);

    /* Only enforce on IPv4 and IPv6 TCP connections */
    if (sa_family != 2 /* AF_INET */ && sa_family != 10 /* AF_INET6 */)
        return 0;

    /*
     * For AF_INET, extract destination IPv4 for C2 blocklist check.
     * struct sockaddr_in { sa_family_t sin_family; __be16 sin_port;
     *                      struct in_addr sin_addr; ... };
     */
    __u32 dst_ipv4 = 0;
    if (sa_family == 2 /* AF_INET */) {
        struct sockaddr_in *sin = (struct sockaddr_in *)address;
        bpf_probe_read_kernel(&dst_ipv4, sizeof(dst_ipv4), &sin->sin_addr.s_addr);
    } else if (sa_family == 10 /* AF_INET6 */) {
        /*
         * For IPv6, check for IPv4-mapped addresses (::ffff:x.x.x.x).
         * struct sockaddr_in6 { ... struct in6_addr sin6_addr; };
         * in6_addr.in6_u.u6_addr32[3] contains the IPv4 address if
         * bytes 10-11 are 0xFFFF.
         */
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)address;
        __u16 mapped_marker = 0;
        bpf_probe_read_kernel(&mapped_marker, sizeof(mapped_marker),
                              (char *)&sin6->sin6_addr + 10);
        if (mapped_marker == 0xFFFF || mapped_marker == 0xFFFFU) {
            bpf_probe_read_kernel(&dst_ipv4, sizeof(dst_ipv4),
                                  (char *)&sin6->sin6_addr + 12);
        }
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid  = (__u32)(pid_tgid >> 32);
    __u32 ppid = get_ppid();

    /*
     * Policy A: Block ALL outbound TCP for quarantined PIDs.
     */
    __u8 *q_action = lookup_quarantine(pid, ppid);
    if (q_action && *q_action >= QUARANTINE_ACTION_LOG) {
        __u8 act = *q_action;

        /* Check if this is a TCP socket (SOCK_STREAM = 1) */
        __u8 sock_type = BPF_CORE_READ(sock, type);
        /* SOCK_STREAM enum equals 1 in the kernel */
        if (sock_type == 1) {
            if (act >= QUARANTINE_ACTION_SIGSTOP)
                bpf_send_signal(SIGSTOP);
            emit_block_event(pid, ppid, VALKYRIE_LSM_SOCKET_CONNECT, 0,
                             act, "[BLOCKED_OUTBOUND_TCP]");
            return -EPERM;
        }
    }

    /*
     * Policy B: Block connections to known C2 IPs for ANY process.
     * This applies regardless of quarantine status.
     */
    if (dst_ipv4 != 0) {
        __u8 *c2_flag = bpf_map_lookup_elem(&blocked_c2_ips, &dst_ipv4);
        if (c2_flag && *c2_flag != 0) {
            /* Emit telemetry – this PID is connecting to a known C2 */
            emit_block_event(pid, ppid, VALKYRIE_LSM_SOCKET_CONNECT,
                             0, QUARANTINE_ACTION_KILL,
                             "[BLOCKED_C2_DESTINATION]");
            return -EACCES;
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  License                                                           */
/* ------------------------------------------------------------------ */
char LICENSE[] SEC("license") = "Dual BSD/GPL";
