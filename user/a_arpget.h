#ifndef A_ARPGET_H
#define A_ARPGET_H 1

#include <stdint.h>
#include <linux/if_ether.h>

int a_get_mac(const char* ifname, const uint32_t src_ip, const char src_mac[ETH_ALEN], const uint32_t dst_ip, char dst_mac[ETH_ALEN]);

#endif
