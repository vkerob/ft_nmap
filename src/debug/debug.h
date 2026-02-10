#ifndef DEBUG_H
#define DEBUG_H

#include "typesdef.h"
#include "scan.h"

void	print_debug_packet_start();

void	print_debug_packet_end();

void	print_debug_ethernet_header(t_eth_hdr *eth_header);

//void	print_debug_icmp_header(struct icmphdr *icmp_hdr);

void	print_debug_protocol(int protocol);

void	print_debug_ethernet_type(int ether_type);

void	print_debug_datalink_type(int datalink_type);

void	print_debug_parsing_args(t_ctx ctx);

void print_debug_iface_info(char (*iface_names)[IFNAMSIZ], size_t iface_count);


#endif
