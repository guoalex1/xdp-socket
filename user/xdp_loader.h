#ifndef XDP_LOADER_H
#define XDP_LOADER_H 1

#include <net/if.h>
#include <xdp/libxdp.h>
#include <bpf/libbpf.h>
#include "uint_map.h"

struct interface_xdp_state {
    struct xdp_program* program;
    struct bpf_link* link;
    int xsk_map_fd;
    int bind_map_fd;
    int ref_count;
};

struct interface_xdp_state* load_xdp_filter(const uint32_t ifindex);

void release_xdp_filter(const uint32_t ifindex);

#endif
