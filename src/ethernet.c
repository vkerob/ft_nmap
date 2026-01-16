
#include "ft_nmap.h"

void	decode_ethernet_packet(uint8_t *datagram, t_ethernet_hdr *eth_hdr)
{
	*eth_hdr = *(t_ethernet_hdr *)datagram;
	(void)eth_hdr;
}
