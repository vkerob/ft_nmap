#ifndef DEBUG_H
#define DEBUG_H

#include "request.h"
#include "scan.h"
#include "shared.h"
#include "typesdef.h"

void print_debug_thread_startup(pthread_t phid, const char *func_name);

void print_debug_thread_leave(pthread_t phid, const char *func_name);

void print_debug_concise_probe(const t_probe *probe);

void print_debug_sender_thread_proceed_probe(pthread_t phid, t_probe *request,
											 struct timeval *tv);

void print_debug_probe_exceed_timeout(const t_probe *probe, const struct timeval *current_time,
	const unsigned long seconds_elapsed);

void print_debug_max_retries_exceeded(t_probe *tmp);

void sync_printf(const char *format, ...);

void print_debug_packet_start();

void print_debug_packet_end();

void print_debug_ethernet_header(t_eth_hdr *eth_header);

// void	print_debug_icmp_header(struct icmphdr *icmp_hdr);

void print_debug_protocol(int protocol);

void print_debug_ethernet_type(int ether_type);

void print_debug_sent_queue_state(u8 iface_index, t_probe_queue *sent);

void print_debug_datalink_type(int datalink_type);

void print_debug_parsing_args(t_ctx ctx);

void print_debug_iface_info(t_iface_info *ifaces, size_t iface_count);

void print_debug_tcp_header(t_tcp_hdr *tcp_hdr);

void print_debug_ip_header(struct ip *ip_hdr);

void print_debug_udp_header(t_udp_hdr *udp_hdr);

void print_debug_probe_request(t_probe *request);

void print_debug_receiver_data(t_receiver_data *receiver_data);

void print_debug_shared_data_probe(t_shared_data_sender *shared_data_probe,
								   t_iface_info			*ifaces);
#endif
