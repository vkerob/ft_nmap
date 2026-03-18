#include "udp.h"

#include <stdlib.h>

void	build_udp_header(struct udphdr *udp_hdr, u16 dest_port)
{
	udp_hdr->uh_sport = htons(1025 + (rand() % 64510)); // 65535 − 1025 = 64510
	udp_hdr->uh_dport = htons(dest_port);
}

