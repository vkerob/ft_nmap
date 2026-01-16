#include "ft_nmap.h"

int	decode_datagram(
	uint8_t *datagram,
	t_ethernet_hdr *eth_hdr,
	struct ip *ip_hdr,
	struct tcphdr *tcp_hdr)
{
	decode_ethernet_packet((uint8_t *)datagram, eth_hdr);
	decode_ip_packet((uint8_t *)&datagram[sizeof(t_ethernet_hdr)], ip_hdr);
	decode_tcp_packet((uint8_t *)&datagram[sizeof(t_ethernet_hdr) + sizeof(struct tcphdr)], tcp_hdr);
	return EXIT_SUCCESS;
}