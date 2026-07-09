//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/string.h>

/*
 * PHANTOM GRID - SINGLE PACKET AUTHORIZATION (SPA) MODULE
 * Zero Trust Access Control - Server is invisible until Magic Packet received
 * 
 * ALL CONFIGURATION IS AUTO-GENERATED FROM Go CONFIG
 * Do not edit constants manually - update internal/config/config.go instead
 * Run 'make generate-config' to regenerate
 */

// Include auto-generated configuration
#include "phantom_ports.h"

// Whitelist map: IP address -> expiration timestamp
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100);  // Max 100 whitelisted IPs
    __type(key, __be32);       // Source IP address
    __type(value, __u64);      // Expiration timestamp (jiffies)
} spa_whitelist SEC(".maps");

// Statistics map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} spa_auth_success SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} spa_auth_failed SEC(".maps");

static __always_inline int is_whitelisted(__be32 src_ip) {
    __u64 *expiry = bpf_map_lookup_elem(&spa_whitelist, &src_ip);
    if (!expiry) {
        return 0;
    }
    
    // Check if whitelist entry has expired
    __u64 current_time = bpf_ktime_get_ns();
    if (current_time > *expiry) {
        // Entry expired, remove it
        bpf_map_delete_elem(&spa_whitelist, &src_ip);
        return 0;
    }
    
    return 1;
}

static __always_inline int verify_magic_packet(void *payload, __u32 payload_len) {
    if (payload_len < SPA_TOKEN_LEN) {
        return 0;
    }
    
    char token[SPA_TOKEN_LEN] = SPA_SECRET_TOKEN;
    if (bpf_strncmp(payload, token, SPA_TOKEN_LEN) == 0) {
        return 1;
    }
    
    return 0;
}

static __always_inline void whitelist_ip(__be32 src_ip) {
    // Calculate expiry time: current time + duration
    __u64 current_time = bpf_ktime_get_ns();
    __u64 expiry = current_time + SPA_WHITELIST_DURATION_NS;
    
    bpf_map_update_elem(&spa_whitelist, &src_ip, &expiry, BPF_ANY);
    
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&spa_auth_success, &key);
    if (val) __sync_fetch_and_add(val, 1);
}

SEC("xdp")
int phantom_spa_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    __be32 src_ip = ip->saddr;

    // Check for Magic Packet (SPA Authentication)
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end) return XDP_DROP;
        
        if (udp->dest == bpf_htons(SPA_MAGIC_PORT)) {
            void *payload = (void *)(udp + 1);
            __u32 payload_len = (__u32)(data_end - (void *)payload);
            
            if (verify_magic_packet(payload, payload_len)) {
                whitelist_ip(src_ip);
                return XDP_DROP;
            } else {
                __u32 key = 0;
                __u64 *val = bpf_map_lookup_elem(&spa_auth_failed, &key);
                if (val) __sync_fetch_and_add(val, 1);
                return XDP_DROP;
            }
        }
    }

    // Check whitelist
    if (is_whitelisted(src_ip)) {
        return XDP_PASS;
    }

    // Default: Drop all traffic (server appears "dead")
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";

