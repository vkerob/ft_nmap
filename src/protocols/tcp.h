
#ifndef TCP_H
#define TCP_H

#include "ip.h"
#include "request.h"
#include "shared.h"
#include "typesdef.h"

#include <stdatomic.h>

void calculate_tcp_checksum(t_ip_pseudo_hdr *ip_pseudo_hdr,
							struct tcphdr	*tcp_hdr);

void build_tcp_header(struct tcphdr *tcp_hdr, uint16_t destination_port,
					  t_scan_type scan_type);

void handle_tcp_response(t_probe_queue *sent_list, u8 flags,
						 t_scan_type scan_type, u16 source_port,
						 struct in_addr ip_src);

void decode_tcp_packet(u8 *datagram, struct tcphdr *tcp_hdr);

void update_port_tcp_header(struct tcphdr *tcp_hdr, u16 port);

void print_debug_tcp_header(t_tcp_hdr *tcp_hdr);

t_scan_type determine_tcp_scan_type(u16 source_port);

u16 get_random_source_port_in_scantype_interval(t_scan_type scan_type);

#endif
