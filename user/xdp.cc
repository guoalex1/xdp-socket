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
static char* dmac = nullptr;
static unsigned int queue = 0;

static in_addr_t saddr = 0;
static in_addr_t daddr = 0;
static uint16_t  sport = 0;
static uint16_t  dport = 0;

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

static void usage(const char* prog) {
    std::cerr << "usage: " << prog << " -i <interface> -q <queue> [-d <destination-mac>]" << std::endl;
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
                                            .bind_flags = XDP_COPY | XDP_USE_NEED_WAKEUP }; // XDP_ZEROCOPY
    SYSCALL(xsk_socket__create(&xsk.socket, iname, queue, xsk.umem, &xsk.rx, &xsk.tx, &scfg));
    xsk.fd = xsk_socket__fd(xsk.socket);

    int map_fd = bpf_obj_get("/sys/fs/bpf/xdp/xsk_filter/xsks_map");
    int sock_fd = xsk_socket__fd(xsk.socket);
    bpf_map_update_elem(map_fd, &queue, &sock_fd, 0);

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

static void send() {
}

static void request(char* packet = nullptr) {
    struct ethhdr* eth = (struct ethhdr*)packet;
    struct  iphdr* iph = (struct  iphdr*)(eth + 1);
    struct udphdr *udp = (struct udphdr*)(iph + 1);
    char* payload      =          (char*)(udp + 1);

    udp->source = 4711;
    udp->dest   = 4711;
    udp->len    = htons(sizeof(*udp));
    udp->check  = 0;

    iph->version = 4;
    iph->ihl = 5;
    iph->protocol = IPPROTO_UDP;
    iph->tot_len = htons(sizeof(*iph) + udp->len);
    iph->ttl = 64;
    iph->daddr = daddr;
    iph->saddr = saddr;
    iph->check = 0; // TODO: checksum_fold(iph, sizeof(*iph), 0);

    eth->h_proto = htons(ETH_P_IP);
}

static void reply() {
}

static void recv() {
    for (;;) {
//        SYSCALLIO(epoll_pwait2(epoll_fd, &epoll_ev, 1, NULL, NULL));
//        struct pollfd fds = { xsk.fd, POLLIN };
//        SYSCALLIO(poll(&fds, 1, -1));
//        SYSCALLIO(recvfrom(xsk.fd, NULL, 0, MSG_DONTWAIT, NULL, NULL));
        __u32 idx;
        __u32 n = xsk_ring_cons__peek(&xsk.rx, 1, &idx);
        for (; n > 0; n -= 1, idx += 1) {
            const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&xsk.rx, idx);
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
                    // --- Parse UDP ---
                    struct udphdr* udp = (struct udphdr*)(iph + 1);
                    std::cout << "UDP packet: " << src_ip << " -> " << dst_ip << ":" << ntohs(udp->source)
                            << " -> " << ntohs(udp->dest) << " | length " << desc->len << std::endl;
                } else {
                    std::cout << "Non UDP packet" << std::endl;
                }

            }

            // std::cout << n << ' ' << idx << ' ' << data << ' ' << desc->len << ' ' << xsk_ring_prod__needs_wakeup(&xsk.fill) << std::endl;

            // process packet here

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
        int option = getopt( argc, argv, "d:i:q:h?" );
        if ( option < 0 ) break;
        switch(option) {
        case 'd':
            dmac = optarg;
            break;
        case 'i':
            iname = optarg;
            break;
        case 'q':
            queue = atoi(optarg);
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

    if (dmac) {
        struct ifaddrs *ifaddr;
        SYSCALL(getifaddrs(&ifaddr));
        for (struct ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
            if (!strcmp(ifa->ifa_name, iname) && ifa->ifa_addr)
            if (ifa->ifa_addr->sa_family == AF_PACKET) {
                struct sockaddr_ll* lladdr = (struct sockaddr_ll*)ifa->ifa_addr;
                assert(lladdr->sll_halen == 6);
                printf("smac: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
                        lladdr->sll_addr[0], lladdr->sll_addr[1], lladdr->sll_addr[2],
                        lladdr->sll_addr[3], lladdr->sll_addr[4], lladdr->sll_addr[5]);
            } else if (ifa->ifa_addr->sa_family == AF_INET) {
                char s[INET_ADDRSTRLEN];
                if (!inet_ntop(AF_INET, &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr, s, INET_ADDRSTRLEN)) {
                    std::cerr << "ERROR: unable to print IP address of interface " << iname << std::endl;
                    exit(1);
                }
                printf("sip: %s\n", s);
            }
        }
        freeifaddrs(ifaddr);
    }

    setup_xdp();

    if (dmac) {
        request();
        recv();
    } else {
        recv();
        reply();
    }
    return 0;
}
