
#ifndef UDP_H
#define UDP_H

#include "ip.h"
#include "request.h"
#include "shared.h"
#include "typesdef.h"

#include <netinet/udp.h>

void	build_udp_header(struct udphdr *udp_hdr, u16 dest_port);

void	calculate_udp_checksum(const t_ip_pseudo_hdr *ip_pseudo_hdr,
	struct udphdr *udp_hdr);

void	handle_udp_response(t_probe_queue *sent_list, u16 source_port, struct in_addr ip_src);

#endif
