#ifndef DEBUG_H
#define DEBUG_H

#include "protocols.h"
#include "request.h"
#include "scan.h"
#include "shared.h"
#include "typesdef.h"

void print_debug_thread_startup(pthread_t phid, const char *func_name);

void print_debug_thread_leave(pthread_t phid, const char *func_name);

void print_debug_concise_probe(const t_probe *probe);

void print_debug_sender_thread_proceed_probe(pthread_t			   phid,
											 const t_probe		  *request,
											 const struct timeval *tv);

void print_debug_probe_exceed_timeout(const t_probe		   *probe,
									  const struct timeval *current_time,
									  const unsigned long	seconds_elapsed);

bool print_debug_packet_send(t_probe *probe, struct timeval *relative_sent_time,
							 t_datalink_hdr *datalink_hdr, t_ip *ip_hdr);

bool print_debug_packet_recv(const struct ip	  *ip_hdr,
							 const t_datalink_hdr *datalink_hdr,
							 const t_datalink_hdr *nested_datalink_hdr,
							 const struct ip	  *nested_ip_hdr,
							 const struct timeval *relative_recv_time);

void print_debug_max_retries_exceeded(const t_probe *tmp);

void sync_printf(const char *format, ...);

void print_debug_packet_start();

void print_debug_packet_end();

void print_debug_ethernet_header(t_eth_hdr *eth_header);

// void	print_debug_icmp_header(struct icmphdr *icmp_hdr);
void print_debug_services(t_port_svc *services_arr[MAX_PROTO_COUNT], u16 port_count, bool tcp_scan, bool udp_scan);

void print_debug_protocol(int protocol);

void print_debug_ethernet_type(int ether_type);

void print_debug_sent_queue_state(u8 iface_index, const t_probe_queue *sent);

void print_debug_datalink_type(int datalink_type);

void print_debug_parsing_args(t_ctx ctx);

void print_debug_iface_info(t_iface_info *ifaces, size_t iface_count);

void print_debug_tcp_header(t_tcp_hdr *tcp_hdr);

void print_debug_ip_header(struct ip *ip_hdr);

void print_debug_udp_header(t_udp_hdr *udp_hdr);

void print_debug_icmp_header(t_icmp_hdr *icmp_hdr);

void print_debug_probe_request(const t_probe *request);

void print_debug_receiver_data(const t_receiver_data *receiver_data);

void print_debug_shared_data_probe(t_shared_data_sender *shared_data_probe,
								   t_iface_info			*ifaces);

void print_debug_definitive_port_state_tcp(t_port_output *port);

char *port_state_to_str(t_port_state state);

#endif
