#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

typedef unsigned char        __u8;
typedef unsigned short       __u16;
typedef unsigned int         __u32;
typedef unsigned long long   __u64;
typedef signed char          __s8;
typedef signed short         __s16;
typedef signed int           __s32;
typedef signed long long     __s64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 pid_t;
typedef __u32 uid_t;
typedef __u32 gid_t;

/*
 * Kernel Networking & XDP Context Definitions
 */
enum xdp_action {
    XDP_ABORTED = 0,
    XDP_DROP    = 1,
    XDP_PASS    = 2,
    XDP_TX      = 3,
    XDP_REDIRECT= 4,
};

struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
} __attribute__((packed));

struct iphdr {
    __u8 ihl:4, version:4;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __sum16 check;
    __be32 saddr;
    __be32 daddr;
};

struct tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u16 res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
};

struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
};

struct in_addr {
    __be32 s_addr;
};

struct in6_addr {
    union {
        __u8 u6_addr8[16];
        __be16 u6_addr16[8];
        __be32 u6_addr32[4];
    } in6_u;
};

struct sockaddr {
    unsigned short sa_family;
    char sa_data[14];
};

struct sockaddr_in {
    unsigned short sin_family;
    __be16 sin_port;
    struct in_addr sin_addr;
    unsigned char sin_zero[8];
};

struct sockaddr_in6 {
    unsigned short sin6_family;
    __be16 sin6_port;
    __be32 sin6_flowinfo;
    struct in6_addr sin6_addr;
    __u32 sin6_scope_id;
};

/*
 * Kernel VFS, Process & LSM Structures (CO-RE Relocatable)
 */
struct qstr {
    const unsigned char *name;
    __u32 len;
};

struct dentry {
    struct dentry *d_parent;
    struct qstr d_name;
};

struct super_block {
    unsigned long s_magic;
};

struct inode {
    unsigned long i_ino;
    struct super_block *i_sb;
};

struct path {
    void *mnt;
    struct dentry *dentry;
};

struct file {
    struct path f_path;
    struct inode *f_inode;
};

struct linux_binprm {
    struct file *file;
    const char *filename;
    const char *interp;
};

struct task_struct {
    pid_t pid;
    pid_t tgid;
    struct task_struct *real_parent;
    char comm[16];
};

struct sock_common {
    __be32 skc_daddr;
    __be32 skc_rcv_saddr;
    unsigned short skc_dport;
    unsigned short skc_family;
};

struct sock {
    struct sock_common __sk_common;
};

struct socket {
    struct sock *sk;
    short type;
};

/*
 * Tracepoint Raw Context
 */
struct trace_entry {
    unsigned short type;
    unsigned char flags;
    unsigned char preempt_count;
    int pid;
};

struct trace_event_raw_sys_enter {
    struct trace_entry ent;
    long int id;
    long unsigned int args[6];
    char __data[0];
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_H__ */
