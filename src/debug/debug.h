#ifndef DEBUG_H
#define DEBUG_H

#include "probe_request.h"
#include "scan.h"
#include "sll.h"
#include "typesdef.h"

void print_debug_packet_start();

void print_debug_packet_end();

void print_debug_ethernet_header(t_eth_hdr *eth_header);

// void	print_debug_icmp_header(struct icmphdr *icmp_hdr);

void print_debug_protocol(int protocol);

void print_debug_ethernet_type(int ether_type);

void print_debug_datalink_type(int datalink_type);

void print_debug_parsing_args(t_ctx ctx);

void print_debug_iface_info(t_iface_info *ifaces, size_t iface_count);

void print_debug_tcp_header(t_tcp_hdr *tcp_hdr);

void print_debug_sll_header(t_sll_hdr *sll_hdr);

void print_debug_sll_protocol(int protocol);

void print_debug_ip_header(struct ip *ip_hdr);

void print_debug_udp_header(t_udp_hdr *udp_hdr);

void print_debug_probe_request(t_probe_request *request);

#endif
