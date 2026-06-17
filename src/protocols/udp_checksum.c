#include "protocols.h"
#include "udp.h"

#include <string.h>

void	calculate_udp_checksum(const t_ip_pseudo_hdr *ip_pseudo_hdr,
	struct udphdr *udp_hdr, const u8 *payload, u16 payload_len)
{
	char	buffer[2048] = { 0 };
	size_t	off = 0;

	memcpy(buffer, ip_pseudo_hdr, sizeof(t_ip_pseudo_hdr));
	off += sizeof(t_ip_pseudo_hdr);
	memcpy(buffer + off, udp_hdr, sizeof(struct udphdr));
	off += sizeof(struct udphdr);
	if (payload != NULL && payload_len > 0)
	{
		memcpy(buffer + off, payload, payload_len);
		off += payload_len;
	}

	udp_hdr->uh_sum = calculate_checksum(buffer, (int)off);
}
