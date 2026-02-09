#ifndef	IP_H
#define IP_H

#include "typesdef.h"
#include "scan.h"

#include <netinet/ip.h>
#include <netinet/in.h>

typedef struct s_ip_pseudo_hdr
{
	struct in_addr	ip_src, ip_dst;
	u8							zero;
	u8							protocol;
	u16							tcp_length;
}	t_ip_pseudo_hdr;

void	build_pseudo_ip_header(
	t_ip_pseudo_hdr *ip_pseudo_hdr,
	const char *dst_addr,
	const char *src_addr);


void	print_debug_ip_header(struct ip *ip_hdr);

#endif
