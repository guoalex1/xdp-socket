#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <stdio.h>

#include "arp.h"
#include "uint_map.h"

#define IPV4_ALEN 4

static uint_map<char[ETH_ALEN]> arp_table;

struct arp {
    unsigned short hw_type;
    unsigned short proto_type;
    unsigned char hw_len;
    unsigned char proto_len;
    unsigned short opcode;
    char src_mac[ETH_ALEN];
    char src_ip[IPV4_ALEN];
    char target_mac[ETH_ALEN];
    char target_ip[IPV4_ALEN];
};

// Send ARP request and wait for reply
static int arp_exchange(int fd, const char src_mac[ETH_ALEN], uint32_t src_ip, uint32_t dst_ip, char out_mac[ETH_ALEN])
{
    unsigned char packet[42];
    memset(packet, 0, sizeof(packet));

    struct ethhdr *eth = (struct ethhdr *) packet;
    struct arp *arp = (struct arp *) (packet + ETH_HLEN);

    // Ethernet header
    memset(eth->h_dest, 0xff, ETH_ALEN);
    memcpy(eth->h_source, src_mac, ETH_ALEN);
    eth->h_proto = htons(ETH_P_ARP);

    // ARP header
    arp->hw_type = htons(ARPHRD_ETHER);
    arp->proto_type = htons(ETH_P_IP);
    arp->hw_len = ETH_ALEN;
    arp->proto_len = IPV4_ALEN;
    arp->opcode = htons(ARPOP_REQUEST);

    memcpy(arp->src_mac, src_mac, ETH_ALEN);
    memcpy(arp->src_ip, &src_ip, IPV4_ALEN);
    memset(arp->target_mac, 0, ETH_ALEN);
    memcpy(arp->target_ip, &dst_ip, IPV4_ALEN);

    // Send request
    if (send(fd, packet, sizeof(packet), 0) < 0) {
        fprintf(stderr, "Error sending ARP request\n");
        return -1;
    }

    // Wait for reply
    for (;;) {
        unsigned char buf[60];
        ssize_t n = recv(fd, buf, sizeof(buf), 0);

        if (n < 42) {
            continue;
        }

        struct ethhdr* reth = (struct ethhdr*)buf;
        struct arp* rarp = (struct arp*)(buf + ETH_HLEN);

        if (ntohs(reth->h_proto) == ETH_P_ARP && ntohs(rarp->opcode) == ARPOP_REPLY && memcmp(rarp->src_ip, &dst_ip, IPV4_ALEN) == 0) {
            memcpy(out_mac, rarp->src_mac, ETH_ALEN);
            return 0;
        }
    }
}

int get_mac(const char* ifname, const uint32_t src_ip, const char src_mac[ETH_ALEN], const uint32_t dst_ip, char dst_mac[ETH_ALEN])
{
    char (*mac)[ETH_ALEN] = map_find(&arp_table, dst_ip);

    if (mac != NULL) {
        memcpy(dst_mac, *mac, sizeof(*mac));
        return 0;
    }

    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

    struct ifreq ifr;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ioctl(sockfd, SIOCGIFINDEX, &ifr);
    int ifindex = ifr.ifr_ifindex;

    struct sockaddr_ll sll;
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ARP);
    sll.sll_ifindex = ifindex;
    bind(sockfd, (struct sockaddr*)&sll, sizeof(sll));

    int ret = arp_exchange(sockfd, src_mac, src_ip, dst_ip, dst_mac);

    if (ret == 0) {
        map_insert_or_assign(&arp_table, dst_ip, (char(*)[ETH_ALEN])dst_mac);
    }

    return ret;
}
