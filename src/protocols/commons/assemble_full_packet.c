#include "protocols.h"

void	assemble_full_packet(u_char *packet, struct ether_header *eth_hdr,
						  struct ip *ip_hdr, struct tcphdr *tcp_hdr,
						  struct udphdr *udp_hdr)
{
	(void)packet;
	(void)eth_hdr;
	(void)ip_hdr;
	(void)tcp_hdr;
	(void)udp_hdr;
}
