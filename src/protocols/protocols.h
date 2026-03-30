
#ifndef PROTOCOLS_H
#define PROTOCOLS_H

#include "typesdef.h"

#include "request.h"
#include "scan.h"
#include "tcp.h"
#include "udp.h"

#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>

typedef union u_datalink_hdr
{
	t_tcp_hdr  tcp_hdr;
	t_udp_hdr  udp_hdr;
	t_icmp_hdr icmp_hdr;
} t_datalink_hdr;

u16 calculate_checksum(void *buffer, int len);

bool find_port_object(t_target *target, t_tcp_hdr *tcp_hdr,
					  t_scan_type scan_type, t_port *port);

void assemble_full_packet(u_char *packet, struct ether_header *eth_hdr,
						  struct ip *ip_hdr, struct tcphdr *tcp_hdr,
						  struct udphdr *udp_hdr);

void handle_response_packet(const t_ip			 *ip_hdr,
							const t_datalink_hdr *datalink_hdr,
							t_probe				 *target);

#endif
