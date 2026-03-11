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
#include <stdbool.h>
#include <string.h>
#include <time.h>

static bool handle_ip_protocol(t_probe_queue *sent_list, t_ip *ip_hdr,
							   bpf_u_int32 l3_caplen)
{
	const u8 *protocol_hdr;
	size_t	  ip_hlen;
	size_t	  l4_len;

	print_debug_ip_header(ip_hdr);
	if (l3_caplen < sizeof(struct ip))
		return true;

	ip_hlen = (size_t)ip_hdr->ip_hl * 4;
	if (ip_hlen < sizeof(struct ip) || l3_caplen < ip_hlen)
		return true;

	protocol_hdr = (const u8 *)ip_hdr + ip_hlen;
	l4_len = l3_caplen - ip_hlen;

	print_debug_protocol(ip_hdr->ip_p);
	switch (ip_hdr->ip_p)
	{
	case IPPROTO_TCP:
		if (l4_len < sizeof(struct tcphdr))
			return true;
		t_tcp_hdr tcp_hdr = *(const struct tcphdr *)protocol_hdr;
		print_debug_tcp_header(&tcp_hdr);
		// idenfy response packet
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
		print_debug_udp_header(&udp_hdr);

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
	print_debug_ethernet_type(ntohs(eth_header->ether_type));
	if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
		return false;

	pkt_ip = (t_ip *)(packet + l2_len);

	print_debug_ethernet_header(eth_header);
	l3_caplen = caplen - l2_len;
	return handle_ip_protocol(sent_list, pkt_ip, (bpf_u_int32)l3_caplen);
}

static bool parse_datalink_layer(pcap_t *handle, t_probe_queue *sent_list,
								 const u_char *packet, bpf_u_int32 caplen)
{
	int datalink_type = pcap_datalink(handle);
	// print_debug_datalink_type(datalink_type);

	if (datalink_type == DLT_EN10MB)
		return handle_with_ethernet(sent_list, packet, caplen);
	return false;
}

void handle_packet(u_char *args, const struct pcap_pkthdr *header,
				   const u_char *packet)
{
	sync_printf(ANSI_COLOR_RED
				"Thread %lu enter handle_packet()\n" ANSI_COLOR_RESET,
				pthread_self());

	t_pcap_user_data *user_data = (t_pcap_user_data *)args;

	t_probe_queue *sent_list = user_data->receiver_data->sent;

	print_debug_packet_start();
	if (!parse_datalink_layer(user_data->handle, sent_list, packet,
							  header->caplen))
		return;
}

static void purge_timedout_probe_request(t_probe_queue *sent,
										 t_probe_queue *to_send)
{
	t_probe *tmp = sent->head;

	pthread_mutex_lock(&sent->mut);
	while (tmp)
	{
		struct timeval current_time;
		gettimeofday(&current_time, NULL);

		unsigned long seconds_elapsed
			= current_time.tv_sec - tmp->timestamp.tv_sec;
		// unsigned long microseconds_elapsed
		// 	= current_time.tv_usec - tmp->timestamp.tv_usec;

		// double time_elapsed = seconds_elapsed + (microseconds_elapsed /
		// (1e6)); printf("elapsed time seconds: %lu microseconds: %lu\n",
		// seconds_elapsed, 	   microseconds_elapsed); printf("time elapsed:
		// %f\n", time_elapsed);

		if (seconds_elapsed > TIMEOUT_DELAY_SECONDS)
		{
			// Erase tmp from the sent list
			erase_reference_to_node(&sent->head, tmp->prev, tmp->next);
			// else if (tmp->next)
			// {
			// 	// Update head and erase prev of next

			// 	tmp->next->prev = NULL;
			// 	sent->head = tmp->next;
			// }

			// Update retries and reinject in to_send probe queue
			if (tmp->retries < MAX_SCAN_RETRIES)
			{
				tmp->retries += 1;
				memset(&tmp->timestamp, 0, sizeof(struct timeval));
			}
			pthread_mutex_lock(&to_send->mut);
			if (to_send->tail)
			{
				to_send->tail->next = tmp;
			}
			else
			{
				to_send->head = tmp;
			}
			// update tail to new request
			to_send->tail = tmp;
			pthread_mutex_unlock(&to_send->mut);
		}
		tmp = tmp->next;
	}
	pthread_mutex_unlock(&sent->mut);
}

void *capture_routine(void *arg)
{
	pthread_t phid;
	phid = pthread_self();
	print_debug_capture_thread_startup(phid);

	t_receiver_data *receiver_data = (t_receiver_data *)arg;
	// TODO: change this
	pcap_t *handle = receiver_data->handle;

	char errbuf[PCAP_ERRBUF_SIZE];
	int	 ret;

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
	ret = pcap_setnonblock(handle, 1, errbuf);
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

	while (!g_stop)
	{
		t_pcap_user_data user_data
			= { .handle = handle, .receiver_data = receiver_data };
		/* Returns 0 if no packet to read */
		if (pcap_dispatch(handle, -1, handle_packet, (u_char *)&user_data) == 0)
		{
			// sync_printf("Thread %lu: no received packet\n");
			purge_timedout_probe_request(receiver_data->sent,
										 receiver_data->to_send);
		}
	}
	print_debug_capture_thread_leave(phid);
	return NULL;
}
