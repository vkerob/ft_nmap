#include "capture.h"
#include "debug.h"
#include "ethernet.h"
#include "icmp.h"
#include "ip.h"
#include "my_signal.h"
#include "protocols.h"
#include "request.h"
#include "sll.h"
#include "tcp.h"
#include "udp.h"

#include <netinet/in.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

// static void handle_with_null_loopback(const u_char *packet)
// {
// 	struct ip *ip_hdr = (struct ip *)packet;
// 	print_debug_ip_header(ip_hdr);
// 	// handle_ip_protocol(ip_hdr);
// }

// static void handle_with_linux_sll(const u_char *packet)
// {
// 	t_sll_hdr *sll_hdr = (t_sll_hdr *)packet;
// 	print_debug_sll_protocol((sll_hdr->sll_protocol));

// 	if (ntohs(sll_hdr->sll_protocol) == ETHERTYPE_IP)
// 	{
// 		struct ip *ip_hdr = (struct ip *)(packet + sizeof(t_sll_hdr));
// 		print_debug_sll_header(sll_hdr);
// 		print_debug_ip_header(ip_hdr);
// 		// handle_ip_protocol(ip_hdr, t);
// 	}
// }

// static bool find_corresponding_target(t_target *targets, size_t
// targets_count, 									  struct in_addr *src_ip,
// t_target *target)
// {
// 	const char *src_ip_addr = inet_ntoa(*src_ip);

// 	/* Maybe there's a quicker way to find the target back using the long
// 	value of the IP rather than with the string notation */

// 	for (size_t i = 0; i < targets_count; i++)
// 	{
// 		if (strcmp(targets[i].ip, src_ip_addr) == 0)
// 		{
// 			target = &targets[i];
// 			(void)target;
// 			return true;
// 		}
// 	}
// 	return false;
// }

static bool handle_ip_protocol(const t_ip *ip_hdr, bpf_u_int32 l3_caplen,
							   t_datalink_hdr *hdr)
{
	const u8 *protocol_hdr;
	size_t	  ip_hlen;
	size_t	  l4_len;

	if (l3_caplen < sizeof(struct ip))
		return false;

	ip_hlen = (size_t)ip_hdr->ip_hl * 4;
	if (ip_hlen < sizeof(struct ip) || l3_caplen < ip_hlen)
		return false;

	protocol_hdr = (const u8 *)ip_hdr + ip_hlen;
	l4_len = l3_caplen - ip_hlen;

	pthread_mutex_lock(&printf_mutex);
	print_debug_protocol(ip_hdr->ip_p);
	switch (ip_hdr->ip_p)
	{
	case IPPROTO_TCP:
		if (l4_len < sizeof(struct tcphdr))
			return false;
		hdr->tcp_hdr = *(const struct tcphdr *)protocol_hdr;
		print_debug_tcp_header(&hdr->tcp_hdr);
		pthread_mutex_unlock(&printf_mutex);

		return true;

	case IPPROTO_UDP:
		if (l4_len < sizeof(struct udphdr))
			return false;
		hdr->udp_hdr = *(const struct udphdr *)protocol_hdr;
		print_debug_udp_header(&hdr->udp_hdr);
		pthread_mutex_unlock(&printf_mutex);
		return true;

	case IPPROTO_ICMP:
		pthread_mutex_unlock(&printf_mutex);
		return true;

	default:
		return false;
	}
}

static bool handle_with_ethernet(const u_char *packet, bpf_u_int32 caplen,
								 t_ip *ip_hdr, t_datalink_hdr *hdr)
{
	struct ether_header *eth_header;
	const t_ip			*pkt_ip;
	size_t				 l2_len;
	size_t				 l3_caplen;

	l2_len = sizeof(struct ether_header);
	if (caplen < l2_len + sizeof(struct ip))
		return false;

	eth_header = (struct ether_header *)packet;
	pthread_mutex_lock(&printf_mutex);
	print_debug_ethernet_type(ntohs(eth_header->ether_type));
	pthread_mutex_unlock(&printf_mutex);

	if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
		return false;

	pkt_ip = (const t_ip *)(packet + l2_len);
	*ip_hdr = *pkt_ip;
	pthread_mutex_lock(&printf_mutex);

	print_debug_ethernet_header(eth_header);
	print_debug_ip_header(ip_hdr);
	pthread_mutex_unlock(&printf_mutex);
	l3_caplen = caplen - l2_len;
	return handle_ip_protocol(pkt_ip, (bpf_u_int32)l3_caplen, hdr);
}

static bool parse_datalink_layer(const u_char *packet, bpf_u_int32 caplen,
								 t_ip *ip_hdr, t_datalink_hdr *datalink_hdr,
								 pcap_t *handle)
{
	int datalink_type = pcap_datalink(handle);
	print_debug_datalink_type(datalink_type);

	if (datalink_type == DLT_EN10MB)
		return handle_with_ethernet(packet, caplen, ip_hdr, datalink_hdr);
	return false;
}

void handle_packet(u_char *args, const struct pcap_pkthdr *header,
				   const u_char *packet)
{
	sync_printf(ANSI_COLOR_RED
				"Thread %lu enter handle_packet()\n" ANSI_COLOR_RESET,
				pthread_self());
	t_pcap_user_data *user_data = (t_pcap_user_data *)args;
	t_receiver_data	 *receiver_data = user_data->receiver_data;

	t_ip		   ip_hdr = { 0 };
	t_datalink_hdr hdr = { 0 };

	t_probe_queue *sent_list = user_data->receiver_data->sent;
	t_probe		  *tmp = sent_list->head;
	t_probe		  *prev;

	// print_debug_packet_start();
	if (!parse_datalink_layer(packet, header->caplen, &ip_hdr, &hdr,
							  user_data->handle))
		return;

	u16 destination_port;
	u16 source_port;
	if (ip_hdr.ip_p == IPPROTO_UDP)
	{
		destination_port = ntohs(hdr.udp_hdr.uh_dport);
		source_port = ntohs(hdr.udp_hdr.uh_sport);
	}
	else
	{
		destination_port = ntohs(hdr.tcp_hdr.th_dport);
		source_port = ntohs(hdr.tcp_hdr.th_sport);
	}

	t_scan_type scan_type = SCAN_UDP;

	printf("Destination Port: %hu\n", destination_port);
	printf("Source Port: %hu\n", source_port);
	printf("Scan type: %u\n", scan_type);
	printf("IP Address Value: %u\n", ip_hdr.ip_src.s_addr);
	if (ip_hdr.ip_p == IPPROTO_TCP)
	{
		scan_type = determine_tcp_scan_type(destination_port);
		if (scan_type == SCAN_UNKNOWN)
		{
			return;
		}
	}
	while (tmp)
	{
		printf(
			ANSI_COLOR_CYAN
			"=============================================\n" ANSI_COLOR_RESET);
		printf("Probe Destination Port: %hu\n", tmp->port);
		printf("Probe Target IP Value: %u\n", tmp->target->addr.s_addr);
		char buf[16];
		scan_type_to_str(tmp->type, buf);
		printf("Probe Scan Type: %s\n", buf);
		printf("Probe Sent Timestamp: %ld.%06d\n", tmp->timestamp.tv_sec,
			   tmp->timestamp.tv_usec);

		printf(ANSI_COLOR_CYAN "============================================"
							   "\n\n" ANSI_COLOR_RESET);
		if (source_port == tmp->port
			&& (scan_type == tmp->type || ip_hdr.ip_p == IPPROTO_UDP)
			&& tmp->target->addr.s_addr == ip_hdr.ip_src.s_addr)
		{
			printf(ANSI_BOLD ANSI_COLOR_YELLOW
				   "Found target\n" ANSI_COLOR_RESET);
			break;
		}
		prev = tmp;
		tmp = tmp->next;
	}
	if (tmp)
	{
		print_debug_probe_request(tmp);
		erase_reference_to_node(prev, tmp->next);
	}
	else
	{
		sent_list->head = NULL;
	}

	// find_corresponding_target();
	// pop_probe_request();
	print_debug_packet_end();

	sync_printf(ANSI_COLOR_RED
				"Thread %lu leave handle_packet()\n" ANSI_COLOR_RESET,
				pthread_self());
	(void)receiver_data;
}

static void purge_timedout_probe_request(t_probe_queue *sent,
										 t_probe_queue *to_send)
{
	time_t	 now;
	t_probe *tmp = sent->head;

	pthread_mutex_lock(&sent->mut);
	while (tmp)
	{
		now = time(NULL);
		unsigned long seconds_elapsed
			= (unsigned long)difftime(now, (time_t)tmp->timestamp.tv_sec);

		if (seconds_elapsed > TIMEOUT_DELAY_SECONDS)
		{
			// Pop tmp from the sent list
			if (tmp->prev)
			{
				// Link previous node with next
				tmp->prev->next = tmp->next;
				tmp->next->prev = tmp->prev;
			}
			else if (tmp->next)
			{
				// Update head and erase prev of next
				tmp->next->prev = NULL;
				sent->head = tmp->next;
			}

			// Update retries and reinject in probe request list
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
			// free probe_request_sent object
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
