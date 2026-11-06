/*
 * K-Valkyrie XDP Network Guard – Line-Rate Packet Filtering
 * File: ebpf_probes/xdp_net_guard.bpf.c
 *
 * Provides instant network quarantine at the XDP layer for wire-speed
 * filtering of known Command & Control IP traffic. Operates before the
 * kernel network stack sees the packet, minimizing latency and CPU overhead.
 *
 * Architecture:
 *  - Parses Ethernet → IPv4 → TCP/UDP headers using direct packet access
 *  - Looks up source and destination IPv4 addresses against blocked_ipv4_addrs
 *  - Drops matching packets (XDP_DROP) and increments per-CPU stats counters
 *  - Passes all other traffic (XDP_PASS)
 *
 * Attachment: XDP_FLAGS_DRV_MODE on the target network interface via libbpf
 *
 * Compile: clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
 *          -I headers/ -c xdp_net_guard.bpf.c -o xdp_net_guard.bpf.o
 */

#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ------------------------------------------------------------------ */
/*  Protocol Constants                                                */
/* ------------------------------------------------------------------ */
#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/* ------------------------------------------------------------------ */
/*  XDP Action Stat Indices                                           */
/* ------------------------------------------------------------------ */
enum xdp_action_idx {
    XDP_STATS_PASS   = 0,
    XDP_STATS_DROP   = 1,
    XDP_STATS_ABORTED = 2,
    XDP_STATS_MAX    = 3, /* Number of stat slots */
};

/* ------------------------------------------------------------------ */
/*  Ethernet & IPv4 Header Layouts (for direct packet access)         */
/*                                                                    */
/*  We define minimal structs to avoid CO-RE relocations on packet    */
/*  data since XDP operates on raw bytes, not kernel structs.         */
/* ------------------------------------------------------------------ */
struct ethhdr_t {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16        h_proto;
} __attribute__((packed));

struct iphdr_t {
    __u8   ihl_version;   /* version (4 bits) + IHL (4 bits) */
    __u8   tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8   ttl;
    __u8   protocol;
    __be16 check;
    __be32 saddr;
    __be32 daddr;
} __attribute__((packed));

/* ------------------------------------------------------------------ */
/*  BPF Maps                                                          */
/* ------------------------------------------------------------------ */

/*
 * LRU hash of blocked IPv4 addresses.
 * Populated by the userspace daemon with known C2 / threat IPs.
 * Key:   __be32 IPv4 address (network byte order)
 * Value: __u8   action flag (non-zero = drop)
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, __be32);
    __type(value, __u8);
} blocked_ipv4_addrs SEC(".maps");

/*
 * Per-CPU counters for XDP action statistics.
 * Index 0 = XDP_PASS count
 * Index 1 = XDP_DROP count
 * Index 2 = XDP_ABORTED count
 * Userspace polls this array to collect throughput and drop metrics.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, XDP_STATS_MAX);
    __type(key, __u32);
    __type(value, __u64);
} xdp_stats SEC(".maps");

/* ------------------------------------------------------------------ */
/*  Inline Helpers                                                    */
/* ------------------------------------------------------------------ */

/*
 * Atomically increment a per-CPU stat counter for the given action.
 */
static __always_inline void record_stat(__u32 action_idx)
{
    __u64 *counter = bpf_map_lookup_elem(&xdp_stats, &action_idx);
    if (counter)
        (*counter) += 1;
}

/* ------------------------------------------------------------------ */
/*  XDP Program: xdp_net_guard                                        */
/* ------------------------------------------------------------------ */
SEC("xdp")
int xdp_net_guard(struct xdp_md *ctx)
{
    void *data     = (void *)(unsigned long)ctx->data;
    void *data_end = (void *)(unsigned long)ctx->data_end;

    /* ---- Layer 2: Ethernet ---- */
    struct ethhdr_t *eth = data;
    if ((void *)(eth + 1) > data_end) {
        record_stat(XDP_STATS_ABORTED);
        return XDP_ABORTED;
    }

    /* Only process IPv4 frames */
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        record_stat(XDP_STATS_PASS);
        return XDP_PASS;
    }

    /* ---- Layer 3: IPv4 ---- */
    struct iphdr_t *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        record_stat(XDP_STATS_ABORTED);
        return XDP_ABORTED;
    }

    /* Verify minimum IPv4 header length (IHL >= 5 → 20 bytes) */
    __u8 ihl = iph->ihl_version & 0x0F;
    if (ihl < 5) {
        record_stat(XDP_STATS_ABORTED);
        return XDP_ABORTED;
    }

    /* Only inspect TCP and UDP packets */
    __u8 proto = iph->protocol;
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
        record_stat(XDP_STATS_PASS);
        return XDP_PASS;
    }

    /*
     * Verify that the transport header is within bounds.
     * IP header length = IHL * 4 bytes.
     */
    void *transport_hdr = (void *)((unsigned char *)iph + (ihl * 4));

    /* For TCP: minimum 20 bytes; for UDP: minimum 8 bytes */
    if (proto == IPPROTO_TCP) {
        if (transport_hdr + 20 > data_end) {
            record_stat(XDP_STATS_ABORTED);
            return XDP_ABORTED;
        }
    } else { /* UDP */
        if (transport_hdr + 8 > data_end) {
            record_stat(XDP_STATS_ABORTED);
            return XDP_ABORTED;
        }
    }

    /* ---- Threat IP Lookup ---- */
    __be32 saddr = iph->saddr;
    __be32 daddr = iph->daddr;

    /* Check source IP against blocklist */
    __u8 *src_flag = bpf_map_lookup_elem(&blocked_ipv4_addrs, &saddr);
    if (src_flag && *src_flag != 0) {
        record_stat(XDP_STATS_DROP);
        return XDP_DROP;
    }

    /* Check destination IP against blocklist */
    __u8 *dst_flag = bpf_map_lookup_elem(&blocked_ipv4_addrs, &daddr);
    if (dst_flag && *dst_flag != 0) {
        record_stat(XDP_STATS_DROP);
        return XDP_DROP;
    }

    /* ---- Clean Traffic: Pass ---- */
    record_stat(XDP_STATS_PASS);
    return XDP_PASS;
}

/* ------------------------------------------------------------------ */
/*  License                                                           */
/* ------------------------------------------------------------------ */
char LICENSE[] SEC("license") = "Dual BSD/GPL";
