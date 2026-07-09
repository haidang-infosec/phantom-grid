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
 * PHANTOM GRID - DYNAMIC SINGLE PACKET AUTHORIZATION (SPA) MODULE
 * Zero Trust Access Control with TOTP + Ed25519/HMAC
 * 
 * This module supports:
 * - Static token (legacy, backward compatible)
 * - Dynamic SPA with TOTP + HMAC-SHA256
 * - Asymmetric SPA with TOTP + Ed25519 (signature verification in user-space)
 * 
 * ALL CONFIGURATION IS AUTO-GENERATED FROM Go CONFIG
 * Do not edit constants manually - update internal/config/config.go instead
 * Run 'make generate-config' to regenerate
 */

// Include auto-generated configuration
#include "phantom_ports.h"

// SPA Packet Structure (binary format)
// Version(1) + Mode(1) + Timestamp(8) + TOTP(4) + Padding(variable) + Signature(32/64)
#define SPA_PACKET_VERSION 1
#define SPA_MODE_STATIC 0
#define SPA_MODE_DYNAMIC 1
#define SPA_MODE_ASYMMETRIC 2
#define SPA_PACKET_HEADER_SIZE 14  // Version(1) + Mode(1) + Timestamp(8) + TOTP(4)
#define SPA_HMAC_SIG_SIZE 32
#define SPA_ED25519_SIG_SIZE 64

// Whitelist map: IP address -> expiration timestamp
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100);  // Max 100 whitelisted IPs
    __type(key, __be32);       // Source IP address
    __type(value, __u64);      // Expiration timestamp (nanoseconds)
} spa_whitelist SEC(".maps");

// Anti-Replay Protection: signature hash -> timestamp
// Prevents replay attacks by tracking used signatures
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000);  // Max 1000 replay entries
    __type(key, __u64);          // First 8 bytes of signature hash
    __type(value, __u64);        // Timestamp when seen
} spa_replay_protection SEC(".maps");

// TOTP Secret (loaded from user-space)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 32);     // 32 bytes for TOTP secret
    __type(key, __u32);
    __type(value, __u8);
} spa_totp_secret SEC(".maps");

// HMAC Secret (for dynamic mode)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 32);     // 32 bytes for HMAC secret
    __type(key, __u32);
    __type(value, __u8);
} spa_hmac_secret SEC(".maps");

// SPA Configuration (loaded from user-space)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} spa_config SEC(".maps");
// Config keys:
// 0: TOTP time step (seconds)
// 1: TOTP tolerance (steps)
// 2: Replay window (seconds)
// 3: Current SPA mode (0=static, 1=dynamic, 2=asymmetric)

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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} spa_replay_blocked SEC(".maps");

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

// Check replay protection
static __always_inline int check_replay_protection(void *signature, __u32 sig_len) {
    if (sig_len < 8) return 0; // Need at least 8 bytes for hash
    
    // Use first 8 bytes of signature as key
    __u64 sig_hash = 0;
    __u8 *sig_bytes = (__u8 *)signature;
    #pragma clang loop unroll(full)
    for (int i = 0; i < 8 && i < sig_len; i++) {
        sig_hash = (sig_hash << 8) | sig_bytes[i];
    }
    
    __u64 *seen_time = bpf_map_lookup_elem(&spa_replay_protection, &sig_hash);
    if (seen_time) {
        // Signature already seen - check if within replay window
        __u64 current_time = bpf_ktime_get_ns();
        __u32 replay_window_key = 2;
        __u32 *replay_window_sec = bpf_map_lookup_elem(&spa_config, &replay_window_key);
        if (replay_window_sec) {
            __u64 replay_window_ns = (__u64)(*replay_window_sec) * 1000000000ULL;
            if (current_time - *seen_time < replay_window_ns) {
                // Replay detected!
                __u32 key = 0;
                __u64 *val = bpf_map_lookup_elem(&spa_replay_blocked, &key);
                if (val) __sync_fetch_and_add(val, 1);
                return 1; // Replay detected
            }
        }
    }
    
    // Not seen before or outside replay window - add to map
    __u64 current_time = bpf_ktime_get_ns();
    bpf_map_update_elem(&spa_replay_protection, &sig_hash, &current_time, BPF_ANY);
    return 0; // Not a replay
}

// Verify static token (legacy mode)
static __always_inline int verify_static_token(void *payload, __u32 payload_len) {
    if (payload_len < SPA_TOKEN_LEN) {
        return 0;
    }
    
    const char *token = SPA_SECRET_TOKEN;
    if (bpf_strncmp(payload, token, SPA_TOKEN_LEN) == 0) {
        return 1;
    }
    
    return 0;
}

// Parse and validate dynamic SPA packet
// Returns: 1 if valid, 0 if invalid
// Note: Full signature verification for Ed25519 must be done in user-space
// This function only validates packet structure and TOTP
static __always_inline int verify_dynamic_packet(void *payload, __u32 payload_len, __be32 src_ip) {
    if (payload_len < SPA_PACKET_HEADER_SIZE) {
        return 0;
    }
    
    __u8 *p = (__u8 *)payload;
    
    // Check version
    if (p[0] != SPA_PACKET_VERSION) {
        return 0;
    }
    
    __u8 mode = p[1];
    
    // Extract timestamp and TOTP
    __u64 timestamp = 0;
    #pragma clang loop unroll(full)
    for (int i = 0; i < 8; i++) {
        timestamp = (timestamp << 8) | p[2 + i];
    }
    
    __u32 totp = 0;
    #pragma clang loop unroll(full)
    for (int i = 0; i < 4; i++) {
        totp = (totp << 8) | p[10 + i];
    }
    
    // Determine signature size
    __u32 sig_size = 0;
    if (mode == SPA_MODE_DYNAMIC) {
        sig_size = SPA_HMAC_SIG_SIZE;
    } else if (mode == SPA_MODE_ASYMMETRIC) {
        sig_size = SPA_ED25519_SIG_SIZE;
    } else {
        return 0; // Unknown mode
    }
    
    // Check packet size
    if (payload_len < SPA_PACKET_HEADER_SIZE + sig_size) {
        return 0;
    }
    
    // Extract signature for replay protection
    void *signature = (void *)(p + payload_len - sig_size);
    
    // Check replay protection
    if (check_replay_protection(signature, sig_size)) {
        return 0; // Replay attack detected
    }
    
    // Validate TOTP (simplified - full validation in user-space)
    // For now, we just check that TOTP is present and packet structure is valid
    // Full TOTP validation and signature verification happens in user-space
    
    // Note: This is a simplified check. Full verification requires:
    // 1. TOTP validation (needs secret from map)
    // 2. Signature verification (Ed25519/HMAC)
    // These are done in user-space for security and complexity reasons
    
    return 1; // Packet structure valid, pass to user-space for full verification
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
int phantom_spa_dynamic_prog(struct xdp_md *ctx) {
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
            
            // Check SPA mode from config
            __u32 config_key = 3; // SPA mode
            __u32 *spa_mode = bpf_map_lookup_elem(&spa_config, &config_key);
            
            if (!spa_mode || *spa_mode == SPA_MODE_STATIC) {
                // Legacy static token mode
                if (verify_static_token(payload, payload_len)) {
                    whitelist_ip(src_ip);
                    return XDP_DROP;
                }
            } else {
                // Dynamic/Asymmetric mode
                if (verify_dynamic_packet(payload, payload_len, src_ip)) {
                    // Packet structure valid - pass to user-space for full verification
                    // User-space will verify TOTP and signature, then whitelist IP
                    // For now, we pass it through (user-space will handle)
                    return XDP_PASS; // Let user-space verify
                }
            }
            
            // Authentication failed
            __u32 key = 0;
            __u64 *val = bpf_map_lookup_elem(&spa_auth_failed, &key);
            if (val) __sync_fetch_and_add(val, 1);
            return XDP_DROP;
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

