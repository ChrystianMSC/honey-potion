// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_ENTRIES 1024
#define THRESHOLD_BYTES 1000
#define ETH_P_IP 0x0800


char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u8);
    __type(value, __u64);
} protocol_bytes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} src_ip_bytes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");


struct anomaly_event {
    __u32 src_ip;
    __u64 total_bytes;
};

SEC("xdp")
int monitor_packets(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u8 proto = ip->protocol;
    __u32 src_ip = ip->saddr;
    __u64 pkt_len = data_end - data;

    __u64 *val = bpf_map_lookup_elem(&protocol_bytes, &proto);
    if (val)
        __sync_fetch_and_add(val, pkt_len);
    else
        bpf_map_update_elem(&protocol_bytes, &proto, &pkt_len, BPF_ANY);

    val = bpf_map_lookup_elem(&src_ip_bytes, &src_ip);
    if (val) {
        *val += pkt_len;
        if (*val > THRESHOLD_BYTES) {
            struct anomaly_event evt = { .src_ip = src_ip, .total_bytes = *val };
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        }
    } else {
        bpf_map_update_elem(&src_ip_bytes, &src_ip, &pkt_len, BPF_ANY);
    }

    return XDP_PASS;
}
