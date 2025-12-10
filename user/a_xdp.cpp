#include <ifaddrs.h>         // getifaddrs, freeifaddrs
#include <linux/if_link.h>   // XDP_FLAGS_SKB_MODE
#include <linux/if_packet.h> // struct sockaddr_ll
#include <net/if.h>          // IF_NAMESIZE
#include <netinet/if_ether.h>// struct ethhdr
#include <netinet/ip.h>      // struct iphdr
#include <netinet/udp.h>     // struct udphdr
#include <poll.h>            // poll
#include <sys/mman.h>        // mmap
#include <xdp/xsk.h>
#include <bpf/bpf.h>
#include <fcntl.h>

#include <cassert>
#include <csignal>
#include <cstring>
#include <iostream>
#include <algorithm>

#include "a_xdp.h"
#include "a_arpget.h"
#include "uint_map.h"

#define TESTING_ENABLE_ASSERTIONS 1
#include "syscall_macro.h"

struct xsk_queue {
    struct xsk_ring_prod tx;
    struct xsk_ring_cons comp;
    struct xsk_ring_prod fill;
    struct xsk_ring_cons rx;
    struct xsk_socket* socket;
    struct xsk_umem* umem;
    void* buffer;
    int fd;
    uint32_t queue = 0;
    char ifname[IF_NAMESIZE];
    char smac[ETH_ALEN];
    uint32_t saddr = 0;
    uint16_t sport = 0;
    uint32_t daddr = 0;
    uint16_t dport = 0;
    int status_flags = 0;
    int queue_length = 16;
    int buffer_size = 0;
};

static uint_map<xsk_queue> fd_to_xsk = {};

struct filter_addr_config {
    uint32_t ip;
    uint16_t port;
};

static const uint32_t configKey = 0;

static uint32_t checksum_nofold(void* data, size_t len, uint32_t sum)
{
	uint16_t* words = (uint16_t*)data;

	for (size_t i = 0; i < len / 2; i++) {
		sum += words[i];
    }

	if (len & 1) {
		sum += ((unsigned char*)data)[len - 1];
    }

	return sum;
}

static uint16_t checksum_fold(void* data, size_t len, uint32_t sum)
{
	sum = checksum_nofold(data, len, sum);

	while (sum > 0xFFFF) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

	return ~sum;
}

static void release_tx(xsk_queue* xsk) {
    uint32_t idx = 0;
    int completed = xsk_ring_cons__peek(&xsk->comp, xsk->queue_length, &idx);
    if (completed > 0) {
        xsk_ring_cons__release(&xsk->comp, completed);
    }
}

// Returns size
static uint32_t setup_ipv4_pkt(void* data, const void* buf, size_t len, uint32_t daddr, uint16_t dport, const char* smac, const char* dmac, uint32_t saddr, uint16_t sport) {
    struct ethhdr* eth = (struct ethhdr*)data;
    struct iphdr* iph = (struct iphdr*)(eth + 1);
    struct udphdr* udph = (struct udphdr*)(iph + 1);
    char* payload = (char*)(udph + 1);

    memcpy(payload, buf, len);

    memcpy(eth->h_source, smac, ETH_ALEN);
    memcpy(eth->h_dest, dmac, ETH_ALEN);
    eth->h_proto = htons(ETH_P_IP);

    udph->source = (sport == 0) ? dport : sport;
    udph->dest = dport;
    udph->len = htons(sizeof(struct udphdr) + len);

    iph->version = 4;
    iph->ihl = 5;
    iph->protocol = IPPROTO_UDP;
    iph->tot_len = htons(sizeof(*iph) + sizeof(*udph) + len);
    iph->ttl = 64;
    iph->daddr = daddr;
    iph->saddr = saddr;
    iph->check = checksum_fold(iph, sizeof(*iph), 0);

    uint32_t sum = (iph->saddr >> 16) & 0xFFFF;
    sum += (iph->saddr) & 0xFFFF;
    sum += (iph->daddr >> 16) & 0xFFFF;
    sum += (iph->daddr) & 0xFFFF;
    sum = checksum_nofold(udph, sizeof(*udph) + len, sum);
    sum += htons(IPPROTO_UDP);
    sum += udph->len;
    udph->check = checksum_fold(NULL, 0, sum);

    return sizeof(*eth) + sizeof(*iph) + sizeof(*udph) + len;
}

void a_init_config(struct a_socket_config* config) {
    if (config != nullptr) {
        config->queue = 0;
        config->queue_length = 16;
        config->xdp_flags = 0;
    }
}

int a_socket(int socket_family, int socket_type, int protocol, const struct a_socket_config* config) {
    if (socket_type != SOCK_DGRAM || config == nullptr || config->ifname == nullptr) {
        return socket(socket_family, socket_type, protocol);
    }

    xsk_queue xsk{};
    int buffer_size = XSK_UMEM__DEFAULT_FRAME_SIZE * config->queue_length * 2;
    xsk.buffer = mmap(NULL, buffer_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    assert(xsk.buffer != MAP_FAILED);


    const struct xsk_umem_config ucfg = { .fill_size = config->queue_length, .comp_size = config->queue_length, .frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE };
    SYSCALL(xsk_umem__create(&xsk.umem, xsk.buffer, buffer_size, &xsk.fill, &xsk.comp, &ucfg));

    const struct xsk_socket_config scfg = { .rx_size = config->queue_length,
                                            .tx_size = config->queue_length,
                                            .libbpf_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD, // don't load default xdp program
                                            .xdp_flags = config->xdp_flags,
                                            .bind_flags = XDP_COPY | XDP_USE_NEED_WAKEUP }; // XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP
    SYSCALL(xsk_socket__create(&xsk.socket, config->ifname, config->queue, xsk.umem, &xsk.rx, &xsk.tx, &scfg));
    xsk.fd = xsk_socket__fd(xsk.socket);

    uint32_t idx;
    uint32_t cnt = xsk_ring_prod__reserve(&xsk.fill, config->queue_length, &idx);
    if (idx != 0 || cnt != config->queue_length) {
        std::cerr << "ERROR: RX fill ring failed: " << cnt << ' ' << idx << std::endl;
        return -1;
    }
    // fill ring is second half of umem
    uint64_t reladdr = XSK_UMEM__DEFAULT_FRAME_SIZE * config->queue_length;
    for (size_t i = 0; i < config->queue_length; i += 1) {
        *xsk_ring_prod__fill_addr(&xsk.fill, i) = reladdr;
        reladdr += XSK_UMEM__DEFAULT_FRAME_SIZE;
    }
    xsk_ring_prod__submit(&xsk.fill, config->queue_length);

    xsk.queue = config->queue;
    strncpy(xsk.ifname, config->ifname, sizeof(xsk.ifname));
    xsk.queue_length = config->queue_length;
    xsk.buffer_size = buffer_size;

    struct ifaddrs* ifaddr;
    SYSCALL(getifaddrs(&ifaddr));
    for (struct ifaddrs* ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!strcmp(ifa->ifa_name, config->ifname) && ifa->ifa_addr) {
            if (ifa->ifa_addr->sa_family == AF_PACKET) {
                struct sockaddr_ll* lladdr = (struct sockaddr_ll*)ifa->ifa_addr;
                assert(lladdr->sll_halen == ETH_ALEN);
                memcpy(xsk.smac, lladdr->sll_addr, ETH_ALEN);
            }

            if (ifa->ifa_addr->sa_family == AF_INET) {
                xsk.saddr = ((struct sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr;
            }
        }
    }

    freeifaddrs(ifaddr);

    map_insert_or_assign(&fd_to_xsk, xsk.fd, &xsk);
    return xsk.fd;
}

int a_bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    xsk_queue* xsk = map_find(&fd_to_xsk, sockfd);

    if (xsk == NULL) {
        return bind(sockfd, addr, addrlen);
    }

    struct filter_addr_config config{};

    if (addr->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in* sin = (struct sockaddr_in*)addr;
        config.ip = sin->sin_addr.s_addr;
        config.port = sin->sin_port;
        xsk->sport = sin->sin_port;
    } else {
        return -1;
    }

    // xsks_map
    int map_fd = bpf_obj_get("/sys/fs/bpf/xdp/xsk_filter/xsks_map");
    int sock_fd = xsk_socket__fd(xsk->socket);
    bpf_map_update_elem(map_fd, &xsk->queue, &sock_fd, BPF_ANY);

    // config_map
    int config_fd = bpf_obj_get("/sys/fs/bpf/xdp/xsk_filter/config_map");
    if (config_fd < 0) {
        std::cerr << "Error getting config_map" << std::endl;
        return -1;
    }

    if (bpf_map_update_elem(config_fd, &configKey, &config, BPF_ANY) < 0) {
        std::cerr << "bpf_map_update_elem config_map" << std::endl;
        return -1;
    }

    return 0;
}

int a_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    xsk_queue* xsk = map_find(&fd_to_xsk, sockfd);

    if (xsk == NULL) {
        return connect(sockfd, addr, addrlen);
    }

    xsk->daddr = ((sockaddr_in*)addr)->sin_addr.s_addr;
    xsk->dport = ((sockaddr_in*)addr)->sin_port;

    return 0;
}

ssize_t a_sendto(int sockfd, const void* buf, size_t size, int flags, const struct sockaddr* dest_addr, socklen_t addrlen) {
    xsk_queue* xsk = map_find(&fd_to_xsk, sockfd);

    if (xsk == NULL) {
        return sendto(sockfd, buf, size, flags, dest_addr, addrlen);
    }

    if (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + size > XSK_UMEM__DEFAULT_FRAME_SIZE) {
        errno = EMSGSIZE;
        return -1;
    }

    uint32_t daddr = (dest_addr == nullptr) ? xsk->daddr : ((sockaddr_in*)dest_addr)->sin_addr.s_addr;
    uint16_t dport = (dest_addr == nullptr) ? xsk->dport : ((sockaddr_in*)dest_addr)->sin_port;

    char dmac[ETH_ALEN] = {0};
    if (a_get_mac(xsk->ifname, xsk->saddr, xsk->smac, daddr, dmac) != 0) {
        return -1;
    }

    release_tx(xsk);
    static uint32_t next_frame = 0;
    const uint64_t frame_offset = next_frame * XSK_UMEM__DEFAULT_FRAME_SIZE;
    next_frame = (next_frame + 1) % xsk->queue_length;

    void* data = xsk_umem__get_data(xsk->buffer, frame_offset);

    const uint32_t frame_size = setup_ipv4_pkt(data, buf, size, daddr, dport, xsk->smac, dmac, xsk->saddr, xsk->sport);

    uint32_t idx;
    if (xsk_ring_prod__reserve(&xsk->tx, 1, &idx) == 1) {
        struct xdp_desc* tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, idx);
        tx_desc->addr = frame_offset;
        tx_desc->len = frame_size;
        xsk_ring_prod__submit(&xsk->tx, 1);
        SYSCALLIO(sendto(xsk->fd, nullptr, 0, MSG_DONTWAIT, nullptr, 0));
        return size;
    }

    return -1;
}

ssize_t a_send(int sockfd, const void* buf, size_t size, int flags) {
    return a_sendto(sockfd, buf, size, flags, nullptr, 0);
}

ssize_t a_recvfrom(int sockfd, void* buf, size_t size, int flags, struct sockaddr* src_addr, socklen_t* addrlen) {
    xsk_queue* xsk = map_find(&fd_to_xsk, sockfd);

    if (xsk == NULL) {
        return recvfrom(sockfd, buf, size, flags, src_addr, addrlen);
    }

    if (!((flags & MSG_DONTWAIT) || (xsk->status_flags & O_NONBLOCK))) {
        struct pollfd fds = { xsk->fd, POLLIN };
        SYSCALLIO(poll(&fds, 1, -1));
    }

    uint32_t idx;
    uint32_t n = xsk_ring_cons__peek(&xsk->rx, 1, &idx);
    if (n < 1) {
        errno = EAGAIN;
        return -1;
    }

    const struct xdp_desc* desc = xsk_ring_cons__rx_desc(&xsk->rx, idx);
    uint64_t addr = xsk_umem__add_offset_to_addr(desc->addr);
    void* data = xsk_umem__get_data(xsk->buffer, addr);
    addr = xsk_umem__extract_addr(desc->addr);
    xsk_ring_cons__release(&xsk->rx, 1);

    // XDP filter guarantees IPv4 UDP packets
    struct ethhdr* eth = (struct ethhdr*)data;
    struct iphdr* iph = (struct iphdr*)(eth + 1);
    struct udphdr* udph = (struct udphdr*)(iph + 1);
    void* payload = (void*)(udph + 1);
    size_t payload_size = desc->len - ((uint8_t*)payload - (uint8_t*)data);

    int copy_size = std::min(size, payload_size);
    memcpy(buf, payload, copy_size);

    if (src_addr != nullptr && addrlen != nullptr && *addrlen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in* sin = (struct sockaddr_in*)src_addr;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = iph->saddr;
        sin->sin_port = udph->source;
        *addrlen = sizeof(struct sockaddr_in);
    }

    if (xsk_ring_prod__reserve(&xsk->fill, 1, &idx) == 1) {
        *xsk_ring_prod__fill_addr(&xsk->fill, idx) = addr;
        xsk_ring_prod__submit(&xsk->fill, 1);
    }

    return copy_size;
}

ssize_t a_recv(int sockfd, void* buf, size_t size, int flags) {
    return a_recvfrom(sockfd, buf, size, flags, nullptr, nullptr);
}

int a_close(int fd) {
    xsk_queue* xsk = map_find(&fd_to_xsk, fd);

    if (xsk == NULL) {
        return close(fd);
    }

    if (xsk->socket != NULL) {
        xsk_socket__delete(xsk->socket);
    }

    if (xsk->umem != NULL) {
        xsk_umem__delete(xsk->umem);
    }

    if (xsk->buffer != NULL) {
        munmap(xsk->buffer, xsk->buffer_size);
    }

    map_erase(&fd_to_xsk, fd);

    return 0;
}

int a_fcntl(int fd, int cmd, ...) {
    int result;
    va_list args;
    va_start(args, cmd);

    xsk_queue* xsk = map_find(&fd_to_xsk, fd);

    if (xsk == NULL) {
        switch (cmd) {
            case F_GETFL:
            case F_GETFD: {
                result = fcntl(fd, cmd);
                break;
            }
            case F_SETFL: {
                int flags = va_arg(args, int);
                result = fcntl(fd, cmd, flags);
                break;
            }
            case F_DUPFD: {
                int min_fd = va_arg(args, int);
                result = fcntl(fd, cmd, min_fd);
                break;
            }
            case F_SETLK:
            case F_SETLKW:
            case F_GETLK: {
                struct flock* fl = va_arg(args, struct flock*);
                result = fcntl(fd, cmd, fl);
                break;
            }
            default: {
                void* arg = va_arg(args, void*);
                result = fcntl(fd, cmd, arg);
                break;
            }
        }
    } else {
        switch (cmd) {
        case F_GETFL: {
            result = xsk->status_flags;
            break;
        }
        case F_SETFL: {
            int flags = va_arg(args, int);
            xsk->status_flags |= flags;
            result = 0;
            return flags;
        }
        default: {
            errno = EINVAL;
            result = -1;
            break;
        }
        }
    }

    va_end(args);
    return result;
}

int a_getsockopt(int sockfd, int level, int optname, void* optval, socklen_t* optlen) {
    if (map_find(&fd_to_xsk, sockfd) == NULL) {
        return getsockopt(sockfd, level, optname, optval, optlen);
    }

    return -1;
}

int a_setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen) {
    if (map_find(&fd_to_xsk, sockfd) == NULL) {
        return setsockopt(sockfd, level, optname, optval, optlen);
    }

    return -1;
}
