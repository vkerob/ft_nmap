
#ifndef UDP_H
#define UDP_H

#include "typesdef.h"

#include <netinet/udp.h>

void	print_debug_udp_header(t_udp_hdr *udp_hdr);

void	build_udp_header(struct udphdr *udp_hdr, uint16_t dest_port);

#endif
