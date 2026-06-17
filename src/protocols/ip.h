#ifndef IP_H
#define IP_H

#include "scan.h"
#include "typesdef.h"
#include "request.h"

#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdatomic.h>

typedef struct s_ip_pseudo_hdr
{
	struct in_addr ip_src, ip_dst;
	u8			   zero;
	u8			   protocol;
	u16			   length;
} t_ip_pseudo_hdr;

int build_pseudo_ip_header(t_ip_pseudo_hdr *ip_pseudo_hdr,
							const char *dst_addr, const char *src_addr, u8 protocol);

void build_ip_header(t_ip *ip_hdr, const t_probe *request,
					 struct in_addr src_ip, _Atomic uint16_t *id_counter);

u16	calculate_checksum(const void *buffer, int len);


#endif
