#include <arpa/inet.h>       // inet_ntop
#include <ifaddrs.h>         // getifaddrs, freeifaddrs
#include <linux/if_packet.h> // struct sockaddr_ll
#include <net/if.h>          // if_nametoindex
#include <netinet/if_ether.h>// struct ethhdr
#include <netinet/ip.h>      // struct iphdr
#include <netinet/udp.h>     // struct udphdr
#include <poll.h>            // poll
#include <sys/epoll.h>       // epoll
#include <sys/mman.h>        // mmap
#include <unistd.h>          // getopt, exit
#include <xdp/xsk.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>

#include <cassert>
#include <csignal>
#include <cstring>
#include <iostream>

#define TESTING_ENABLE_ASSERTIONS 1
#include "syscall_macro.h"

static char* iname = nullptr;
static unsigned int queue = 0;

static in_addr_t saddr = 0;
static in_addr_t daddr = 0;

static unsigned char smac[ETH_ALEN] = {0};
static unsigned char dmac[ETH_ALEN] = {0};
static bool sender = false;

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
};

static struct xsk_queue xsk = {0};

static int epoll_fd = -1;
static struct epoll_event epoll_ev = {0};

struct addressConfig {
    uint32_t ip;
    uint16_t port;
};

static uint16_t port = 0;
static const uint32_t configKey = 0;

static void usage(const char* prog) {
    std::cerr << "usage: " << prog << " -i <interface> -q <queue> -p <port> [-d <destination-mac>] [-a <destination-ip>]" << std::endl;
}

static uint32_t checksum_nofold(void* data, size_t len, uint32_t sum)
{
	uint16_t* words = (uint16_t*)data;

	for (int i = 0; i < len / 2; i++)
		sum += words[i];

	if (len & 1)
		sum += ((unsigned char*)data)[len - 1];

	return sum;
}

static uint16_t checksum_fold(void* data, size_t len, uint32_t sum)
{
	sum = checksum_nofold(data, len, sum);

	while (sum > 0xFFFF)
        sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum;
}

static inline void swap_mac(struct ethhdr* eth)
{
    unsigned char tmp[ETH_ALEN];
    memcpy(tmp, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, tmp, ETH_ALEN);
}


static void cleanup() {
    if (xsk.socket) xsk_socket__delete(xsk.socket);
}

static void exit_signal(int) {
    exit(1);
}

static void setup_pkt() {
}

static void setup_xdp() {
    xsk.buffer = mmap(NULL, BufferSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    assert(xsk.buffer != MAP_FAILED);

    const struct xsk_umem_config ucfg = { .fill_size = QueueLength, .comp_size = QueueLength, .frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE };
    SYSCALL(xsk_umem__create(&xsk.umem, xsk.buffer, BufferSize, &xsk.fill, &xsk.comp, &ucfg));

    const struct xsk_socket_config scfg = { .rx_size = QueueLength,
                                            .tx_size = QueueLength,
                                            .libbpf_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD, // don't load default xdp program
                                            .xdp_flags = XDP_FLAGS_SKB_MODE, // XDP_FLAGS_DRV_MODE
                                            .bind_flags = XDP_COPY | XDP_USE_NEED_WAKEUP }; // XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP
    SYSCALL(xsk_socket__create(&xsk.socket, iname, queue, xsk.umem, &xsk.rx, &xsk.tx, &scfg));
    xsk.fd = xsk_socket__fd(xsk.socket);

    // xsks_map
    int map_fd = bpf_obj_get("/sys/fs/bpf/xdp/xsk_filter/xsks_map");
    int sock_fd = xsk_socket__fd(xsk.socket);
    bpf_map_update_elem(map_fd, &queue, &sock_fd, BPF_ANY);

    // config_map
    int config_fd = bpf_obj_get("/sys/fs/bpf/xdp/xsk_filter/config_map");
    if (config_fd < 0) {
        std::cerr << "Error getting config_map" << std::endl;
        exit(1);
    }

    struct addressConfig config{saddr, htons(port)};

    if (bpf_map_update_elem(config_fd, &configKey, &config, BPF_ANY) < 0) {
        std::cerr << "bpf_map_update_elem config_map" << std::endl;
        exit(1);
    }

    __u32 idx;
    __u32 cnt = xsk_ring_prod__reserve(&xsk.fill, QueueLength, &idx);
    if (idx != 0 || cnt != QueueLength) {
        std::cerr << "ERROR: RX fill ring failed: " << cnt << ' ' << idx << std::endl;
        exit(1);
    }
    // fill ring is second half of umem
    __u64 reladdr = XSK_UMEM__DEFAULT_FRAME_SIZE * QueueLength;
    for (int i = 0; i < QueueLength; i += 1) {
        *xsk_ring_prod__fill_addr(&xsk.fill, i) = reladdr;
        reladdr += XSK_UMEM__DEFAULT_FRAME_SIZE;
    }
    xsk_ring_prod__submit(&xsk.fill, QueueLength);

    epoll_fd = SYSCALLIO(epoll_create1(EPOLL_CLOEXEC));
    epoll_ev.events = EPOLLIN;
    epoll_ev.data.fd = xsk.fd;
    SYSCALL(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, xsk.fd, &epoll_ev));
}

static void release_tx() {
    uint32_t idx = 0;
    int completed = xsk_ring_cons__peek(&xsk.comp, QueueLength, &idx);
    if (completed > 0) {
        xsk_ring_cons__release(&xsk.comp, completed);
    }
}

static void send(const void* buf, size_t len) {
    release_tx();
    static uint32_t next_frame = 0;
    const uint64_t frame_offset = next_frame * XSK_UMEM__DEFAULT_FRAME_SIZE;
    next_frame = (next_frame + 1) % QueueLength;

    void* data = xsk_umem__get_data(xsk.buffer, frame_offset);

    struct ethhdr* eth = (struct ethhdr*)data;
    struct iphdr*  iph = (struct iphdr*)(eth + 1);
    struct udphdr* udp = (struct udphdr*)(iph + 1);
    char* payload       = (char*)(udp + 1);

    memcpy(payload, buf, len);

    memcpy(eth->h_source, smac, ETH_ALEN);
    memcpy(eth->h_dest, dmac, ETH_ALEN);
    eth->h_proto = htons(ETH_P_IP);

    udp->source = htons(port);
    udp->dest   = htons(port);
    udp->len    = htons(sizeof(struct udphdr) + len);
    udp->check  = 0;

    iph->version = 4;
    iph->ihl = 5;
    iph->protocol = IPPROTO_UDP;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + len);
    iph->ttl = 64;
    iph->daddr = daddr;
    iph->saddr = saddr;
    iph->check = checksum_fold(iph, sizeof(*iph), 0);

    const uint32_t frame_len = sizeof(*eth) + sizeof(*iph) + sizeof(*udp) + len;

    uint32_t idx;
    if (xsk_ring_prod__reserve(&xsk.tx, 1, &idx) == 1) {
        struct xdp_desc* tx_desc = xsk_ring_prod__tx_desc(&xsk.tx, idx);
        tx_desc->addr = frame_offset;
        tx_desc->len  = frame_len;
        xsk_ring_prod__submit(&xsk.tx, 1);
        SYSCALLIO(sendto(xsk.fd, nullptr, 0, MSG_DONTWAIT, nullptr, 0));
        std::cout << "Sent UDP packet (" << frame_len << " bytes)" << std::endl;
    }
}

static void request() {
    std::string req = "test";
    send(req.data(), req.size());
}

static void reply(const struct xdp_desc* desc, uint64_t addr) {
    release_tx();
    uint32_t idx = 0;
    if (xsk_ring_prod__reserve(&xsk.tx, 1, &idx) == 1) {
        std::cout << "Reply" << std::endl;
        struct xdp_desc* tx_desc = xsk_ring_prod__tx_desc(&xsk.tx, idx);
        tx_desc->addr = addr;
        tx_desc->len = desc->len;
        xsk_ring_prod__submit(&xsk.tx, 1);
        SYSCALLIO(sendto(xsk.fd, nullptr, 0, MSG_DONTWAIT, nullptr, 0));
    }
}

static void recv() {
    static size_t count = 0;
    for (;;) {
//        SYSCALLIO(epoll_pwait2(epoll_fd, &epoll_ev, 1, NULL, NULL));
//        struct pollfd fds = { xsk.fd, POLLIN };
//        SYSCALLIO(poll(&fds, 1, -1));
//        SYSCALLIO(recvfrom(xsk.fd, NULL, 0, MSG_DONTWAIT, NULL, NULL));
        __u32 idx;
        __u32 n = xsk_ring_cons__peek(&xsk.rx, 1, &idx);
        for (; n > 0; n -= 1, idx += 1) {
            const struct xdp_desc* desc = xsk_ring_cons__rx_desc(&xsk.rx, idx);
            __u64 addr = xsk_umem__add_offset_to_addr(desc->addr);
            void* data = xsk_umem__get_data(xsk.buffer, addr);
            addr = xsk_umem__extract_addr(desc->addr);
            xsk_ring_cons__release(&xsk.rx, 1);

            struct ethhdr* eth = (struct ethhdr*)data;
            if (ntohs(eth->h_proto) == ETH_P_IP) {
                struct iphdr* iph = (struct iphdr*)(eth + 1);
                char src_ip[INET_ADDRSTRLEN];
                char dst_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &iph->saddr, src_ip, sizeof(src_ip));
                inet_ntop(AF_INET, &iph->daddr, dst_ip, sizeof(dst_ip));

                if (iph->protocol == IPPROTO_UDP) {
                    struct udphdr* udp = (struct udphdr*)(iph + 1);
                    ++count;
                    std::cout << "UDP packet " << count << ": " << src_ip << " -> " << dst_ip << ":" << ntohs(udp->source)
                            << " -> " << ntohs(udp->dest) << " | length " << desc->len << std::endl;
                    char* payload = (char*)(udp + 1);
                    size_t payload_len = desc->len - ((uint8_t*)payload - (uint8_t*)data);

                    std::string udp_data(payload, payload_len);
                    std::cout << "Payload string: \"" << udp_data << "\"" << std::endl;
                } else {
                    std::cout << "Non UDP packet" << std::endl;
                }
            }

            if (xsk_ring_prod__reserve(&xsk.fill, 1, &idx) == 1) {
                *xsk_ring_prod__fill_addr(&xsk.fill, idx) = addr;
                xsk_ring_prod__submit(&xsk.fill, 1);
            }
        }
    }
}

static void recycle(void* pkt);

int main(int argc, char** argv) {
    for (;;) {
        int option = getopt( argc, argv, "d:i:q:p:a:h?" );
        if ( option < 0 ) break;
        switch(option) {
        case 'd':
            int vals[ETH_ALEN];
            if (sscanf(optarg, "%x:%x:%x:%x:%x:%x", &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]) != ETH_ALEN) {
                std::cerr << "Invalid MAC address\n";
                exit(1);
            }

            for (int i = 0; i < ETH_ALEN; i++) {
                dmac[i] = (unsigned char)vals[i];
            }

            sender = true;
            break;
        case 'i':
            iname = optarg;
            break;
        case 'q':
            queue = atoi(optarg);
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 'a':
            if (inet_pton(AF_INET, optarg, &daddr) != 1) {
                std::cerr << "Invalid dest IP address: " << optarg << std::endl;
                exit(1);
            }
            break;
        case 'h':
        case '?':
            usage(argv[0]);
            exit(1);
        default:
            std::cerr << "unknown option: -" << (char)option << std::endl;
            usage(argv[0]);
            exit(1);
        }
    }
    if (argc != optind) {
        std::cerr << "unknown argument: " << argv[optind] << std::endl;
        usage(argv[0]);
        exit(1);
    }
    if (!iname) {
        std::cerr << "ERROR: no interface name given" << std::endl;
        exit(1);
    }

    SYSCALL(atexit(cleanup));
    signal(SIGINT, exit_signal);
    signal(SIGTERM, exit_signal);

    struct ifaddrs* ifaddr;
    SYSCALL(getifaddrs(&ifaddr));
    for (struct ifaddrs* ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!strcmp(ifa->ifa_name, iname) && ifa->ifa_addr) {
            if (ifa->ifa_addr->sa_family == AF_PACKET && sender) {
                struct sockaddr_ll* lladdr = (struct sockaddr_ll*)ifa->ifa_addr;
                assert(lladdr->sll_halen == ETH_ALEN);
                memcpy(smac, lladdr->sll_addr, ETH_ALEN);
                printf("smac: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
                        smac[0], smac[1], smac[2], smac[3], smac[4], smac[5]);
            }

            if (ifa->ifa_addr->sa_family == AF_INET) {
                saddr = ((struct sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr;
            }
        }
    }

    freeifaddrs(ifaddr);

    setup_xdp();

    if (sender) {
        request();
        recv();
    } else {
        recv();
    }
    return 0;
}
