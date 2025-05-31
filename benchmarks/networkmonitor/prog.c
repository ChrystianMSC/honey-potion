#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include "prog.skel.h"
#include "prog.h"

static volatile int exiting = 0;

void handle_signal(int sig) {
    exiting = 1;
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct anomaly_event *evt = data;
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &evt->src_ip, ip_str, sizeof(ip_str));

    printf("Anomaly detected! IP: %s, Bytes: %llu\n", ip_str, evt->total_bytes);
}

int main(int argc, char **argv) {
    struct prog_bpf *skel;
    struct bpf_link *link = NULL;
    int ifindex;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <iface>\n", argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(argv[1]);
    if (ifindex == 0) {
        perror("if_nametoindex");
        return 1;
    }

    signal(SIGINT, handle_signal);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    skel = prog_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    link = bpf_program__attach_xdp(skel->progs.monitor_packets, ifindex);
    if (!link) {
        fprintf(stderr, "Failed to attach XDP program\n");
        return 1;
    }

    printf("Monitoring on interface %s...\n", argv[1]);

    struct perf_buffer *pb = NULL;
    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8, handle_event, NULL, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer\n");
        goto cleanup;
    }

    while (!exiting)
        perf_buffer__poll(pb, 100);

cleanup:
    perf_buffer__free(pb);
    bpf_link__destroy(link);
    prog_bpf__destroy(skel);
    return 0;
}
