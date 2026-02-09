
#include "ethernet.h"

// bonus: for later
// note: build with a spoofed src and dst gateway MAC address
void build_ethernet_header(t_eth_hdr *eth_hdr)
{
	(void)eth_hdr;
	eth_hdr->ether_type = htons(ETHERTYPE_IP);
}

