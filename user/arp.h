#ifndef ARP_H
#define ARP_H 1

#include <stdint.h>
#include <linux/if_ether.h>

int get_mac(const uint32_t ifindex, const uint32_t src_ip, const char src_mac[ETH_ALEN], const uint32_t dst_ip, char dst_mac[ETH_ALEN]);

#endif
