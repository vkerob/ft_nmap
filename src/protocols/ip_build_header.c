#include "ip.h"
#include "request.h"
#include "scan.h"
#include "typesdef.h"

#include <stdatomic.h>

void build_ip_header(t_ip *ip_hdr, t_request *request, char *source_ip,
					 _Atomic uint16_t *id_counter)
{
	(void)ip_hdr;
	(void)request;
	ip_hdr->ip_v = IP_VERSION;
	ip_hdr->ip_hl = IP_IHL;
	ip_hdr->ip_ttl = IP_TTL_DEFAULT;
	ip_hdr->ip_p = (request->type == SCAN_UDP) ? IPPROTO_UDP : IPPROTO_TCP;
	ip_hdr->ip_len = htons(sizeof(struct ip));

	// for ip_off htons(0x4000) sets the DF (Don't Fragment) flag but it's
	// poossible to be rejected by some firewalls
	ip_hdr->ip_off = 0;
	ip_hdr->ip_id = htons(atomic_fetch_add(id_counter, 1));
	// ip_hdr->ip_sum = calculate_checksum(ip_hdr, ip_hdr->ip_hl * 4);
	ip_hdr->ip_src.s_addr = inet_addr(source_ip);
	ip_hdr->ip_dst.s_addr = request->target.ip_addr.s_addr;
	// no priority
	ip_hdr->ip_tos = 0;
}
