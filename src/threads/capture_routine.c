#include "args.h"
#include "capture.h"
#include "debug.h"
#include "ethernet.h"
#include "ip.h"
#include "my_signal.h"
#include "protocols.h"
#include "request.h"
#include "scan.h"
#include "shared.h"
#include "tcp.h"
#include "udp.h"

#include <netinet/in.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>


static bool handle_ip_protocol(t_probe_queue *sent_list, t_ip *ip_hdr,
							   bpf_u_int32 l3_caplen)
{
	const u8 *protocol_hdr;
	size_t	  ip_hlen;
	size_t	  l4_len;

	// print_debug_ip_header(ip_hdr);
	if (l3_caplen < sizeof(struct ip))
		return true;

	ip_hlen = (size_t)ip_hdr->ip_hl * 4;
	if (ip_hlen < sizeof(struct ip) || l3_caplen < ip_hlen)
		return true;

	protocol_hdr = (const u8 *)ip_hdr + ip_hlen;
	l4_len = l3_caplen - ip_hlen;

	// print_debug_protocol(ip_hdr->ip_p);
	switch (ip_hdr->ip_p)
	{
	case IPPROTO_TCP:
		if (l4_len < sizeof(struct tcphdr))
			return true;
		t_tcp_hdr tcp_hdr = *(const struct tcphdr *)protocol_hdr;
		// print_debug_tcp_header(&tcp_hdr);
		// print_debug_packet_end();
		// identify response packet
		// handle if it's the response packet in sent queue
		u16			source_port = ntohs(tcp_hdr.th_sport);
		t_scan_type scan_type
			= determine_tcp_scan_type(ntohs(tcp_hdr.th_dport));
		handle_tcp_response(sent_list, tcp_hdr.th_flags, scan_type, source_port,
							ip_hdr->ip_src);

		return false;

	case IPPROTO_UDP:
		if (l4_len < sizeof(struct udphdr))
			return false;
		t_udp_hdr udp_hdr = *(const struct udphdr *)protocol_hdr;
		// print_debug_udp_header(&udp_hdr);
		(void)udp_hdr;

		return false;

	case IPPROTO_ICMP:
		return false;

	default:
		return true;
	}
}

static bool handle_with_ethernet(t_probe_queue *sent_list, const u_char *packet,
								 bpf_u_int32 caplen)
{
	struct ether_header *eth_header;
	t_ip				*pkt_ip;
	size_t				 l2_len;
	size_t				 l3_caplen;

	l2_len = sizeof(struct ether_header);
	if (caplen < l2_len + sizeof(struct ip))
		return false;

	eth_header = (struct ether_header *)packet;
	// print_debug_ethernet_type(ntohs(eth_header->ether_type));
	if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
		return false;

	pkt_ip = (t_ip *)(packet + l2_len);

	// print_debug_ethernet_header(eth_header);
	l3_caplen = caplen - l2_len;
	return handle_ip_protocol(sent_list, pkt_ip, (bpf_u_int32)l3_caplen);
}

static bool parse_datalink_layer(pcap_t *handle, t_probe_queue *sent_list,
								 const u_char *packet, bpf_u_int32 caplen)
{
	const int datalink_type = pcap_datalink(handle);
	// print_debug_datalink_type(datalink_type);

	if (datalink_type == DLT_EN10MB)
		return handle_with_ethernet(sent_list, packet, caplen);
	return false;
}

void handle_packet(u_char *args, const struct pcap_pkthdr *header,
				   const u_char *packet)
{
	pthread_t phid = pthread_self();

	print_debug_thread_startup(phid, __FUNCTION__);
	const t_pcap_user_data *user_data = (t_pcap_user_data *)args;
	const t_receiver_data	 *receiver_data = user_data->receiver_data;

	(void)receiver_data;
	t_probe_queue *sent_list = user_data->receiver_data->sent;

	// print_debug_packet_start();
	parse_datalink_layer(user_data->handle, sent_list, packet,
							  header->caplen);
	print_debug_thread_leave(phid, __FUNCTION__);
}

bool purge_timedout_probe_request(t_probe_queue *sent,
										 t_probe_queue *to_send)
{
	t_probe *tmp = sent->head;
	t_probe *next = NULL;

	pthread_t phid = pthread_self();


	print_debug_thread_startup(phid, __FUNCTION__);
	pthread_mutex_lock(&sent->mut);
	while (tmp)
	{
		struct timeval current_time;
		gettimeofday(&current_time, NULL);

		const unsigned long seconds_elapsed
			= current_time.tv_sec - tmp->timestamp.tv_sec;
		// unsigned long microseconds_elapsed
		// 	= current_time.tv_usec - tmp->timestamp.tv_usec;

		// double time_elapsed = seconds_elapsed + (microseconds_elapsed /
		// (1e6)); printf("elapsed time seconds: %lu microseconds: %lu\n",
		// seconds_elapsed, 	   microseconds_elapsed); printf("time elapsed:
		// %f\n", time_elapsed);

		next = tmp->next;

		print_debug_probe_request(tmp);

		if (seconds_elapsed > TIMEOUT_DELAY_SECONDS)
		{
			print_debug_probe_exceed_timeout(tmp, &current_time, seconds_elapsed);

			// Erase tmp from the sent list
			erase_reference_to_node(&sent->head, tmp->prev, tmp->next);
			// Update retries and reinject in to_send probe queue
			sent->nb_probe--;
			tmp->retries++;

			if (tmp->retries > MAX_SCAN_RETRIES)
			{
				print_debug_max_retries_exceeded(tmp);
				const int index = tmp->target->port_list.port_map[tmp->type][tmp->port];
				t_port *state = &tmp->target->port_list.port_map_rev[tmp->type][index];
				switch (tmp->type)
				{
					case SCAN_SYN:
					case SCAN_ACK:
						state->port_state = FILTERED;
						break;
					case SCAN_FIN:
					case SCAN_NULL:
					case SCAN_XMAS:
						state->port_state = OPEN_FILTERED;
						break ;
					default:
						break ;
				}

				free(tmp);
				tmp = next;
				sync_printf(ANSI_BOLD ANSI_COLOR_MAGENTA "Size of sent queue %d\n" ANSI_COLOR_RESET, sent->nb_probe);
				sync_printf(ANSI_BOLD ANSI_COLOR_MAGENTA "Size of to_send queue %d\n" ANSI_COLOR_RESET, sent->nb_probe);
				continue ;	
			}
			memset(&tmp->timestamp, 0, sizeof(struct timeval));
			pthread_mutex_lock(&to_send->mut);
			tmp->next = NULL;
			// update next of current tail or head if list is empty
			if (to_send->tail){
				tmp->prev = to_send->tail;
				to_send->tail->next = tmp;
			}
			else
			{
				to_send->head = tmp;
			}
			// update tail to new request
			to_send->tail = tmp;
			to_send->nb_probe++;
			pthread_mutex_unlock(&to_send->mut);
		}
		else
		{
			sync_printf(ANSI_BOLD ANSI_COLOR_BLUE "Probe %d did not timeout\n" ANSI_COLOR_RESET, tmp->id);
		}
		tmp = next;
	}
	pthread_mutex_unlock(&sent->mut);
	print_debug_thread_leave(phid, __FUNCTION__);
	return false;
}

void *capture_routine(void *arg)
{
	pthread_t phid = pthread_self();
	print_debug_thread_startup(phid, __FUNCTION__);

	t_receiver_data *receiver_data = arg;
	// TODO: change this
	pcap_t *handle = receiver_data->handle;

	char errbuf[PCAP_ERRBUF_SIZE];

	// sync_printf("test %u\n", pthread_self());

	// const struct timeval *timeout = pcap_get_required_select_timeout(handle);
	// if (timeout == NULL)
	// {
	// 	fprintf(stderr, "timeout not required\n");
	// }
	// else
	// {
	// 	printf("timeout seconds: %ld\n", timeout->tv_sec);
	// 	fflush(stdout);
	// }
	const int ret = pcap_setnonblock(handle, 1, errbuf);
	switch (ret)
	{
	case PCAP_ERROR_NOT_ACTIVATED:
		fprintf(stderr, "pcap_setnonblock: Capture handle is not activated\n");
		return NULL;
	case PCAP_ERROR:
		fprintf(stderr, "pcap_setnonblock: %s\n", errbuf);
		return NULL;
	default:
		break;
	}

	while (!g_stop && (receiver_data->sent->nb_probe != 0 || receiver_data->to_send->nb_probe != 0))
	{
		t_pcap_user_data user_data
			= { .handle = handle, .receiver_data = receiver_data };
		/* Returns 0 if no packet to read */
		if (pcap_dispatch(handle, -1, handle_packet, (u_char *)&user_data) == 0)
		{
			// sync_printf("Thread %lu: no received packet\n");
			if (purge_timedout_probe_request(receiver_data->sent,
									 receiver_data->to_send))
				return NULL;
			sleep(1);
		}
	}
	print_debug_thread_leave(phid, __FUNCTION__);
	return NULL;
}
