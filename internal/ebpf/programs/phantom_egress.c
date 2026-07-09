//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/string.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>

/*
 * PHANTOM GRID - EGRESS DATA LOSS PREVENTION (DLP) MODULE
 * 
 * ALL CONFIGURATION IS AUTO-GENERATED FROM Go CONFIG
 * Do not edit constants manually - update internal/config/config.go instead
 * Run 'make generate-config' to regenerate
 */

// Include auto-generated configuration
#include "phantom_ports.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} egress_blocks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u64);
} suspicious_patterns SEC(".maps");

// Manual string comparison for eBPF verification
static __always_inline int check_pattern(void *data, const char *pattern, __u32 len) {
    unsigned char *d = (unsigned char *)data;
    const unsigned char *p = (const unsigned char *)pattern;
    
    #pragma clang loop unroll(full)
    for (__u32 i = 0; i < 20; i++) { 
        if (i >= len) break;
        if (d[i] != p[i]) return 0;
    }
    return 1;
}

// Detect suspicious data patterns
static __always_inline int detect_suspicious_pattern(void *data, __u32 data_len) {
    if (data_len == 0 || data_len > MAX_PAYLOAD_SCAN) return 0;
    
    // Check for /etc/passwd format
    char p1[] = "root:x:0:0:";
    if (data_len >= 11 && check_pattern(data, p1, 11)) return 1;
    
    // Check for SSH private key
    char p2[] = "-----BEGIN";
    if (data_len >= 10 && check_pattern(data, p2, 10)) return 2;
    
    // Check for Base64 (threshold 95% to avoid false positives)
    __u32 base64_count = 0;
    for (__u32 i = 0; i < data_len && i < 64; i++) {
        char c = ((char *)data)[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || 
            (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
            base64_count++;
        }
    }
    if (base64_count * 100 > data_len * 95 && data_len > 64) return 3;
    
    // Check for SQL dump
    char p4[] = "INSERT INTO";
    if (data_len >= 11 && check_pattern(data, p4, 11)) return 4;
    
    return 0;
}

SEC("tc")
int phantom_egress_prog(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
    if (ip->protocol != IPPROTO_TCP) return TC_ACT_OK;
    
    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;
    
    // Only check data from honeypot port
    if (tcp->source != bpf_htons(HONEYPOT_PORT)) return TC_ACT_OK;
    
    __u32 tcp_hdr_len = (tcp->doff) * 4;
    void *tcp_start = (void *)tcp;
    void *payload = (void *)((char *)tcp_start + tcp_hdr_len);
    if (payload > data_end) return TC_ACT_OK;
    
    __u32 payload_len = (__u32)(data_end - payload);
    if (payload_len == 0) return TC_ACT_OK;
    if (payload_len > MAX_PAYLOAD_SCAN) payload_len = MAX_PAYLOAD_SCAN;
    
    int pattern_type = detect_suspicious_pattern(payload, payload_len);
    
    if (pattern_type > 0) {
        __u32 key = 0;
        __u64 *val = bpf_map_lookup_elem(&egress_blocks, &key);
        if (val) __sync_fetch_and_add(val, 1);
        
        __u32 pattern_key = (__u32)pattern_type;
        __u64 *pattern_val = bpf_map_lookup_elem(&suspicious_patterns, &pattern_key);
        if (pattern_val) __sync_fetch_and_add(pattern_val, 1);

        // Return TC_ACT_OK for demo mode (use TC_ACT_SHOT to actually block)
        return TC_ACT_OK; 
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";