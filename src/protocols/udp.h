
#ifndef UDP_H
#define UDP_H

#include "ip.h"
#include "request.h"
#include "shared.h"
#include "typesdef.h"

#include <netinet/udp.h>
#include <stddef.h>

void build_udp_header(struct udphdr *udp_hdr, u16 dest_port, u16 payload_len);

void calculate_udp_checksum(const t_ip_pseudo_hdr *ip_pseudo_hdr,
							struct udphdr *udp_hdr, const u8 *payload,
							u16 payload_len);

void handle_udp_response(t_probe_queue *sent_list, u16 source_port,
						 struct in_addr ip_src, t_eth_hdr *eth_hdr);

#endif
