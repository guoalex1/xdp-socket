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

#include <cassert>
#include <csignal>
#include <cstring>
#include <iostream>
#include <unordered_map>
#include <algorithm>

#include "a_xdp.h"
#include "a_arpget.h"

#define TESTING_ENABLE_ASSERTIONS 1
#include "syscall_macro.h"

static const unsigned int QueueLength = 16;
static const unsigned int BufferSize = XSK_UMEM__DEFAULT_FRAME_SIZE * QueueLength * 2;

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
};

static std::unordered_map<int, xsk_queue> fd_to_xsk = {};

struct addressConfig {
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

static void release_tx(xsk_queue& xsk) {
    uint32_t idx = 0;
    int completed = xsk_ring_cons__peek(&xsk.comp, QueueLength, &idx);
    if (completed > 0) {
        xsk_ring_cons__release(&xsk.comp, completed);
    }
}

// Returns size
// TODO: Add check for buf len
static uint32_t setup_ipv4_pkt(void* data, const void* buf, size_t len, const sockaddr_in* addr, const char* smac, const char* dmac, uint32_t saddr) {
    struct ethhdr* eth = (struct ethhdr*)data;
    struct iphdr*  iph = (struct iphdr*)(eth + 1);
    struct udphdr* udph = (struct udphdr*)(iph + 1);
    char* payload       = (char*)(udph + 1);

    memcpy(payload, buf, len);

    memcpy(eth->h_source, smac, ETH_ALEN);
    memcpy(eth->h_dest, dmac, ETH_ALEN);
    eth->h_proto = htons(ETH_P_IP);

    udph->source = addr->sin_port;
    udph->dest   = addr->sin_port;
    udph->len    = htons(sizeof(struct udphdr) + len);

    iph->version = 4;
    iph->ihl = 5;
    iph->protocol = IPPROTO_UDP;
    iph->tot_len = htons(sizeof(*iph) + sizeof(*udph) + len);
    iph->ttl = 64;
    iph->daddr = addr->sin_addr.s_addr;
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

int a_socket(const char* ifname, uint32_t queue) {
    if (ifname == nullptr) {
        return -1;
    }

    xsk_queue xsk{};
    xsk.buffer = mmap(NULL, BufferSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    assert(xsk.buffer != MAP_FAILED);

    const struct xsk_umem_config ucfg = { .fill_size = QueueLength, .comp_size = QueueLength, .frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE };
    SYSCALL(xsk_umem__create(&xsk.umem, xsk.buffer, BufferSize, &xsk.fill, &xsk.comp, &ucfg));

    const struct xsk_socket_config scfg = { .rx_size = QueueLength,
                                            .tx_size = QueueLength,
                                            .libbpf_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD, // don't load default xdp program
                                            .xdp_flags = XDP_FLAGS_SKB_MODE, // XDP_FLAGS_DRV_MODE
                                            .bind_flags = XDP_COPY | XDP_USE_NEED_WAKEUP }; // XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP
    SYSCALL(xsk_socket__create(&xsk.socket, ifname, queue, xsk.umem, &xsk.rx, &xsk.tx, &scfg));
    xsk.fd = xsk_socket__fd(xsk.socket);

    uint32_t idx;
    uint32_t cnt = xsk_ring_prod__reserve(&xsk.fill, QueueLength, &idx);
    if (idx != 0 || cnt != QueueLength) {
        std::cerr << "ERROR: RX fill ring failed: " << cnt << ' ' << idx << std::endl;
        return -1;
    }
    // fill ring is second half of umem
    uint64_t reladdr = XSK_UMEM__DEFAULT_FRAME_SIZE * QueueLength;
    for (size_t i = 0; i < QueueLength; i += 1) {
        *xsk_ring_prod__fill_addr(&xsk.fill, i) = reladdr;
        reladdr += XSK_UMEM__DEFAULT_FRAME_SIZE;
    }
    xsk_ring_prod__submit(&xsk.fill, QueueLength);

    xsk.queue = queue;
    strncpy(xsk.ifname, ifname, sizeof(xsk.ifname));

    struct ifaddrs* ifaddr;
    SYSCALL(getifaddrs(&ifaddr));
    for (struct ifaddrs* ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!strcmp(ifa->ifa_name, ifname) && ifa->ifa_addr) {
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

    fd_to_xsk[xsk.fd] = xsk;
    return xsk.fd;
}

int a_bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    if (fd_to_xsk.count(sockfd) == 0) {
        return bind(sockfd, addr, addrlen);
    }

    xsk_queue& xsk = fd_to_xsk[sockfd];

    struct addressConfig config{};

    if (addr->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in* sin = (struct sockaddr_in*)addr;
        config.ip = xsk.saddr;
        config.port = sin->sin_port;
    } else {
        return -1;
    }

    // xsks_map
    int map_fd = bpf_obj_get("/sys/fs/bpf/xdp/xsk_filter/xsks_map");
    int sock_fd = xsk_socket__fd(xsk.socket);
    bpf_map_update_elem(map_fd, &xsk.queue, &sock_fd, BPF_ANY);

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

ssize_t a_sendto(int sockfd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen) {
    if (dest_addr == nullptr || fd_to_xsk.count(sockfd) == 0) {
        return sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    }

    xsk_queue& xsk = fd_to_xsk[sockfd];

    char dmac[ETH_ALEN] = {0};
    if (a_get_mac(xsk.ifname, xsk.saddr, xsk.smac, ((sockaddr_in*)dest_addr)->sin_addr.s_addr, dmac) != 0) {
        return -1;
    }

    release_tx(xsk);
    static uint32_t next_frame = 0;
    const uint64_t frame_offset = next_frame * XSK_UMEM__DEFAULT_FRAME_SIZE;
    next_frame = (next_frame + 1) % QueueLength;

    void* data = xsk_umem__get_data(xsk.buffer, frame_offset);

    const uint32_t frame_len = setup_ipv4_pkt(data, buf, len, (sockaddr_in*)dest_addr, xsk.smac, dmac, xsk.saddr);

    uint32_t idx;
    if (xsk_ring_prod__reserve(&xsk.tx, 1, &idx) == 1) {
        struct xdp_desc* tx_desc = xsk_ring_prod__tx_desc(&xsk.tx, idx);
        tx_desc->addr = frame_offset;
        tx_desc->len  = frame_len;
        xsk_ring_prod__submit(&xsk.tx, 1);
        SYSCALLIO(sendto(xsk.fd, nullptr, 0, MSG_DONTWAIT, nullptr, 0));
        return len;
    }

    return -1;
}

ssize_t a_recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen) {
    if (fd_to_xsk.count(sockfd) == 0) {
        return recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    }

    xsk_queue& xsk = fd_to_xsk[sockfd];

    if (!(flags & MSG_DONTWAIT)) {
        struct pollfd fds = { xsk.fd, POLLIN };
        SYSCALLIO(poll(&fds, 1, -1));
    }

    uint32_t idx;
    uint32_t n = xsk_ring_cons__peek(&xsk.rx, 1, &idx);
    if (n < 1) {
        errno = EAGAIN;
        return -1;
    }

    const struct xdp_desc* desc = xsk_ring_cons__rx_desc(&xsk.rx, idx);
    uint64_t addr = xsk_umem__add_offset_to_addr(desc->addr);
    void* data = xsk_umem__get_data(xsk.buffer, addr);
    addr = xsk_umem__extract_addr(desc->addr);
    xsk_ring_cons__release(&xsk.rx, 1);

    // XDP filter guarantees IPv4 UDP packets
    struct ethhdr* eth = (struct ethhdr*)data;
    struct iphdr* iph = (struct iphdr*)(eth + 1);
    struct udphdr* udph = (struct udphdr*)(iph + 1);
    void* payload = (void*)(udph + 1);
    size_t payload_len = desc->len - ((uint8_t*)payload - (uint8_t*)data);

    int copy_size = std::min(len, payload_len);
    memcpy(buf, payload, copy_size);

    if (src_addr != nullptr && addrlen != nullptr && *addrlen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in* sin = (struct sockaddr_in*)src_addr;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = iph->saddr;
        sin->sin_port = udph->source;
        *addrlen = sizeof(struct sockaddr_in);
    }

    if (xsk_ring_prod__reserve(&xsk.fill, 1, &idx) == 1) {
        *xsk_ring_prod__fill_addr(&xsk.fill, idx) = addr;
        xsk_ring_prod__submit(&xsk.fill, 1);
    }

    return copy_size;
}

int a_close(int sockfd) {
    if (fd_to_xsk.count(sockfd) == 0) {
        errno = EBADF;
        return -1;
    }

    xsk_queue& xsk = fd_to_xsk[sockfd];

    if (xsk.socket) {
        xsk_socket__delete(xsk.socket);
    }

    if (xsk.umem) {
        xsk_umem__delete(xsk.umem);
    }

    if (xsk.buffer) {
        munmap(xsk.buffer, BufferSize);
    }

    fd_to_xsk.erase(sockfd);

    return 0;
}
