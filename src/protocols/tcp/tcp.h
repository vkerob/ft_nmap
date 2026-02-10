
#ifndef TCP_H
#define TCP_H

#include "typesdef.h"
#include "ip.h"

#include <stdatomic.h>

void				calculate_tcp_checksum(t_ip_pseudo_hdr *ip_pseudo_hdr,
	struct tcphdr	*tcp_hdr);

void				build_tcp_header(
	struct tcphdr *tcp_hdr,
	uint16_t destination_port,
	t_scan_type scan_type);

void				handle_tcp_protocol(t_target *target, t_tcp_hdr *tcp_hdr);

void				decode_tcp_packet(u8 *datagram, struct tcphdr *tcp_hdr);

void				update_port_tcp_header(struct tcphdr *tcp_hdr, u16 port);

void				print_debug_tcp_header(t_tcp_hdr *tcp_hdr);

t_scan_type	determine_tcp_scan_type(u16 source_port);

u16					get_random_source_port_in_scantype_interval(t_scan_type scan_type);

#endif
