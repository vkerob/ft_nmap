#include "ip.h"

#include "request.h"
#include "scan.h"
#include "typesdef.h"

#include <stdatomic.h>

void build_ip_header(t_ip *ip_hdr, t_scan_type type, struct in_addr dst_addr,
					 struct in_addr src_ip, _Atomic uint16_t *id_counter)
{
	ip_hdr->ip_v = IP_VERSION;
	ip_hdr->ip_hl = IP_IHL;
	ip_hdr->ip_ttl = IP_TTL_DEFAULT;
	ip_hdr->ip_p = (type == SCAN_UDP) ? IPPROTO_UDP : IPPROTO_TCP;
	ip_hdr->ip_len = sizeof(struct ip);

	// for ip_off htons(0x4000) sets the DF (Don't Fragment) flag but it's
	// possible to be rejected by some firewalls
	ip_hdr->ip_off = 0;
	ip_hdr->ip_id = htons(atomic_fetch_add(id_counter, 1));
	ip_hdr->ip_src = src_ip;
	ip_hdr->ip_dst.s_addr = dst_addr.s_addr;
	// no priority
	ip_hdr->ip_tos = 0;
	// In linux the checksum is filled by the kernel when using socket raw
	ip_hdr->ip_sum = 0;
}

