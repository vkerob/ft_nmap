
#ifndef UDP_H
#define UDP_H

#include "typesdef.h"
#include "ip.h"

#include <netinet/udp.h>

void	build_udp_header(struct udphdr *udp_hdr, u16 dest_port);

void	calculate_udp_checksum(const t_ip_pseudo_hdr *ip_pseudo_hdr,
	struct udphdr *udp_hdr);

#endif
