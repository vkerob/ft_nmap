#ifndef IP_H
#define IP_H

#include "scan.h"
#include "typesdef.h"

#include <netinet/in.h>
#include <netinet/ip.h>

typedef struct s_ip_pseudo_hdr
{
	struct in_addr ip_src, ip_dst;
	u8			   zero;
	u8			   protocol;
	u16			   tcp_length;
} t_ip_pseudo_hdr;

void build_pseudo_ip_header(t_ip_pseudo_hdr *ip_pseudo_hdr,
							const char *dst_addr, const char *src_addr);

#endif
