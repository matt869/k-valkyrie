#ifndef __K_VALKYRIE_COMMON_EVENTS_H__
#define __K_VALKYRIE_COMMON_EVENTS_H__

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int32_t  __s32;
typedef int64_t  __s64;
#endif

#define TASK_COMM_LEN   16
#define PATH_MAX_LEN    128

/*
 * Well-known syscall numbers & probe event identifiers (x86_64 ABI)
 */
#define VALKYRIE_SYS_EXECVE        59
#define VALKYRIE_SYS_PTRACE        101
#define VALKYRIE_SYS_MEMFD_CREATE  319
#define VALKYRIE_SYS_EXECVEAT      322
#define VALKYRIE_LSM_BPRM_CHECK    1001
#define VALKYRIE_LSM_FILE_OPEN     1002

/*
 * Quarantine Actions written to `quarantined_pids` BPF map
 */
enum quarantine_action {
    QUARANTINE_ACTION_NONE     = 0,
    QUARANTINE_ACTION_LOG      = 1,
    QUARANTINE_ACTION_SIGSTOP  = 2,
    QUARANTINE_ACTION_KILL     = 3,
};

/*
 * Shared Ring Buffer Event Struct:
 * Packed & 64-bit aligned to ensure seamless zero-copy serialization
 * between Ring-0 BPF and userspace (Python ctypes / libbpf / Rust).
 */
struct syscall_event_t {
    __u64 timestamp_ns;          /* CLOCK_MONOTONIC / ktime nanoseconds */
    __u64 cgroup_id;             /* Container cgroup v2 ID */
    __u64 inode;                 /* Inode number of the targeted / executed binary */
    __u32 pid;                   /* Thread group ID (host PID) */
    __u32 ppid;                  /* Parent host PID */
    __u32 uid;                   /* User ID */
    __u32 gid;                   /* Group ID */
    __u32 syscall_id;            /* Syscall ID or LSM Event Code */
    __u32 target_pid;            /* Target PID (e.g. for ptrace attach/peek/poke) */
    __u32 fd_flags;              /* Flags passed to memfd_create / open */
    __u32 action_taken;          /* Quarantine action enforced by kernel */
    char comm[TASK_COMM_LEN];    /* Process command name (truncated to 16 bytes) */
    char filename[PATH_MAX_LEN]; /* Path, binary name, or memfd anonymous name */
} __attribute__((aligned(8)));

#endif /* __K_VALKYRIE_COMMON_EVENTS_H__ */
