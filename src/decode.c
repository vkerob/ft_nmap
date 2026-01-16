#include "ft_nmap.h"

int	decode_datagram(
	u8 *datagram,
	t_ethernet_hdr *eth_hdr,
	struct ip *ip_hdr,
	struct tcphdr *tcp_hdr)
{
	decode_ethernet_packet((u8 *)datagram, eth_hdr);
	decode_ip_packet((u8 *)&datagram[sizeof(t_ethernet_hdr)], ip_hdr);
	decode_tcp_packet((u8 *)&datagram[sizeof(t_ethernet_hdr) + sizeof(struct tcphdr)], tcp_hdr);
	return EXIT_SUCCESS;
}