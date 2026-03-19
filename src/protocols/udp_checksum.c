#include "protocols.h"
#include "udp.h"

#include <string.h>

void	calculate_udp_checksum(const t_ip_pseudo_hdr *ip_pseudo_hdr,
	struct udphdr *udp_hdr)
{
	char	buffer[1024] = { 0 };

	memcpy(buffer, ip_pseudo_hdr, sizeof(t_ip_pseudo_hdr));
	memcpy(buffer + sizeof(t_ip_pseudo_hdr), udp_hdr, sizeof(struct udphdr));

	udp_hdr->uh_sum = calculate_checksum(
		buffer,
		sizeof(struct udphdr) + sizeof(t_ip_pseudo_hdr)
	);
}

