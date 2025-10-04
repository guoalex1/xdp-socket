#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define DEFAULT_QUEUE_IDS 64

#define IPPROTO_UDP 17

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, DEFAULT_QUEUE_IDS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xsks_map SEC(".maps");

struct config {
    __u32 ip;
    __u16 port;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} config_map SEC(".maps");

static const __u32 config_key = 0;

SEC("xdp")
int xdp_xsk_filter(struct xdp_md* ctx)
{
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    struct ethhdr* eth = data;
    if ((void*)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // Check if IPv4 packet
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return XDP_PASS;
    }

    struct iphdr* iph = (void*)eth + sizeof(*eth);
    if ((void*)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    if (iph->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }

    struct udphdr* udph = (struct udphdr*)(iph + 1);
    if ((void*)(udph + 1) > data_end) {
        return XDP_PASS;
    }

    __u32 key = 0;
    struct config* cfg = bpf_map_lookup_elem(&config_map, &config_key);
    if (!cfg) {
        return XDP_PASS;
    }

    bpf_printk("iph->daddr: %d, cfg->ip: %d\n", iph->daddr, cfg->ip);

    bpf_printk("udph->dest: %d, cfg->port: %d\n", udph->dest, cfg->port);

    if (iph->daddr != cfg->ip || udph->dest != cfg->port) {
        return XDP_PASS;
    }

    int ret = bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);

    bpf_printk("UDP packet on queue %d, ret: %d\n", ctx->rx_queue_index, ret);

    return ret;
}


char _license[] SEC("license") = "GPL";
