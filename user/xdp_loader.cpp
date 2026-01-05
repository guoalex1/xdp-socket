#include <errno.h>

#include "xdp_loader.h"

static const char XDP_PROGRAM_FILE[] = "xdp_filter.o";
static const char XDP_PROGRAM_NAME[] = "xdp_xsk_filter";
static const char XDP_SECTION_NAME[] = "xdp";
static const char XSK_MAP_NAME[] = "xsk_map";
static const char BIND_ADDR_MAP_NAME[] = "bind_addr_map";

static uint_map<interface_xdp_state> ifindex_to_xdp_state = {};

struct interface_xdp_state* load_xdp_filter(const uint32_t ifindex)
{
    struct interface_xdp_state* state = map_find(&ifindex_to_xdp_state, ifindex);
    if (state != NULL) {
        ++state->ref_count;
        return state;
    }

    struct interface_xdp_state new_state = {0};

    new_state.program = xdp_program__find_file(XDP_PROGRAM_FILE, XDP_SECTION_NAME, NULL);
    if (libxdp_get_error(new_state.program)) {
        fprintf(stderr, "Error loading XDP program: %s\n", strerror(errno));
        return NULL;
    }

    struct bpf_object* bpf_obj = xdp_program__bpf_obj(new_state.program);

    if (bpf_object__load(bpf_obj) < 0) {
        fprintf(stderr, "Error loading BPF object: %s\n", strerror(errno));
        xdp_program__close(new_state.program);
        return NULL;
    }

    struct bpf_program* bpf_prog = bpf_object__find_program_by_name(bpf_obj, XDP_PROGRAM_NAME);

    if (!bpf_prog) {
        fprintf(stderr, "Error finding program in bpf object\n");
        xdp_program__close(new_state.program);
        return NULL;
    }

    new_state.link = bpf_program__attach_xdp(bpf_prog, ifindex);
    if (libbpf_get_error(new_state.link)) {
        fprintf(stderr, "Error attaching XDP program: %s\n", strerror(errno));
        xdp_program__close(new_state.program);
        return NULL;
    }

    new_state.xsk_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, XSK_MAP_NAME);
    new_state.bind_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, BIND_ADDR_MAP_NAME);

    if (new_state.xsk_map_fd < 0 || new_state.bind_map_fd < 0) {
        fprintf(stderr, "Error finding maps in BPF object\n");
        bpf_link__destroy(new_state.link);
        xdp_program__close(new_state.program);
        return NULL;
    }

    new_state.ref_count = 1;

    return map_insert_or_assign(&ifindex_to_xdp_state, ifindex, &new_state);
}

void release_xdp_filter(const uint32_t ifindex)
{
    struct interface_xdp_state* state = map_find(&ifindex_to_xdp_state, ifindex);
    if (state == NULL) {
        return;
    }

    --state->ref_count;

    if (state->ref_count <= 0) {
        if (state->link) {
            bpf_link__destroy(state->link);
        }

        if (state->program) {
            xdp_program__close(state->program);
        }

        map_erase(&ifindex_to_xdp_state, ifindex);
    }
}
