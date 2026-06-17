#include "udp.h"
#include "udp_payloads.h"

#include <stdlib.h>

void	build_udp_header(struct udphdr *udp_hdr, u16 dest_port, u16 payload_len)
{
	udp_hdr->uh_sport = htons(1025 + (rand() % 64510)); // 65535 − 1025 = 64510
	udp_hdr->uh_dport = htons(dest_port);
	udp_hdr->uh_ulen = htons((u16)(sizeof(*udp_hdr) + payload_len));
}

size_t	get_udp_payloads(u16 dest_port, t_udp_probe_payload *out, size_t max)
{
	size_t n = 0;

	for (size_t i = 0; i < UDP_PAYLOAD_COUNT && n < max; i++)
	{
		if (dest_port >= g_udp_payloads[i].port_lo
			&& dest_port <= g_udp_payloads[i].port_hi)
		{
			out[n].data = g_udp_payloads[i].data;
			out[n].len = g_udp_payloads[i].len;
			n++;
		}
	}
	return n;
}
