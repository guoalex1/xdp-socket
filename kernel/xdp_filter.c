#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define DEFAULT_QUEUE_IDS 64

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#ifndef INADDR_ANY
#define	INADDR_ANY ((__u32)0x00000000)
#endif

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, DEFAULT_QUEUE_IDS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xsk_map SEC(".maps");

struct bind_addr {
    __u32 ip;
    __u16 port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct bind_addr);
    __type(value, __u8); // use as flag
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} bind_addr_map SEC(".maps");

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

    struct bind_addr bind_addr_key = {0};
    bind_addr_key.ip = iph->daddr;
    bind_addr_key.port = udph->dest;

    void* lookup_result = bpf_map_lookup_elem(&bind_addr_map, &bind_addr_key);

    if (!lookup_result) {
        bind_addr_key.ip = INADDR_ANY;
        lookup_result = bpf_map_lookup_elem(&bind_addr_map, &bind_addr_key);
    }

    if (!lookup_result) {
        return XDP_PASS;
    }

    int ret = bpf_redirect_map(&xsk_map, ctx->rx_queue_index, XDP_PASS);

    return ret;
}

char _license[] SEC("license") = "GPL";
