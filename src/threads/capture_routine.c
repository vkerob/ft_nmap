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

	print_debug_protocol(ip_hdr->ip_p);

	switch (ip_hdr->ip_p)
	{
	case IPPROTO_TCP:
		if (l4_len < sizeof(struct tcphdr))
			return false;
		hdr->tcp_hdr = *(const struct tcphdr *)protocol_hdr;
		print_debug_tcp_header(&hdr->tcp_hdr);
		return true;

	case IPPROTO_UDP:
		if (l4_len < sizeof(struct udphdr))
			return false;
		hdr->udp_hdr = *(const struct udphdr *)protocol_hdr;
		print_debug_udp_header(&hdr->udp_hdr);
		return true;

	case IPPROTO_ICMP:
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
	print_debug_ethernet_type(ntohs(eth_header->ether_type));
	if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
		return false;

	pkt_ip = (const t_ip *)(packet + l2_len);
	*ip_hdr = *pkt_ip;

	print_debug_ethernet_header(eth_header);
	print_debug_ip_header(ip_hdr);

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
	t_pcap_user_data *user_data = (t_pcap_user_data *)args;
	t_receiver_data	 *shared_data_pcap = user_data->shared_data_pcap;
	t_ip			  ip_hdr = { 0 };
	t_datalink_hdr	  hdr = { 0 };

	print_debug_packet_start();
	if (!parse_datalink_layer(packet, header->caplen, &ip_hdr, &hdr,
							  user_data->handle))
		return;

	print_debug_packet_end();
	(void)shared_data_pcap;
}

// static void purge_timedout_probe_request(t_probe **head_sent_queue,
// 										 t_probe **head, t_probe **tail,
// 										 pthread_mutex_t *sent_queue_mut,
// 										 pthread_mutex_t *to_send_queue_mut)
// {
// 	time_t	 now;
// 	t_probe *tmp = *head_sent_queue;

// 	pthread_mutex_lock(sent_queue_mut);
// 	while (tmp)
// 	{
// 		now = time(NULL);
// 		unsigned long seconds_elapsed
// 			= (unsigned long)difftime(now, tmp->timestamp);

// 		if (seconds_elapsed > TIMEOUT_DELAY_SECONDS)
// 		{
// 			// Pop tmp from the sent list
// 			if (tmp->prev)
// 			{
// 				// Link previous node with next
// 				tmp->prev->next = tmp->next;
// 				tmp->next->prev = tmp->prev;
// 			}
// 			else if (tmp->next)
// 			{
// 				// Update head and erase prev of next
// 				tmp->next->prev = NULL;
// 				*head_sent_queue = tmp->next;
// 			}
// 			// Update retries and reinject in probe request list
// 			if (tmp->retries < MAX_SCAN_RETRIES)
// 			{
// 				tmp->retries += 1;
// 				tmp->timestamp = 0;
// 			}
// 			pthread_mutex_lock(to_send_queue_mut);
// 			if (*tail)
// 			{
// 				(*tail)->next = tmp;
// 			}
// 			else
// 			{
// 				*head = tmp;
// 			}
// 			// update tail to new request
// 			*tail = tmp;
// 			pthread_mutex_unlock(to_send_queue_mut);
// 			// free probe_request_sent object
// 		}
// 		tmp = tmp->next;
// 	}
// 	pthread_mutex_unlock(sent_queue_mut);
// }

void *capture_routine(void *arg)
{
	pthread_t phid;
	phid = pthread_self();
	print_debug_capture_thread_startup(phid);

	t_receiver_data *shared_data_pcap = (t_receiver_data *)arg;
	// TODO: change this
	pcap_t *handle = shared_data_pcap->handle;

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
			= { .handle = handle, .shared_data_pcap = shared_data_pcap };
		/* Returns 0 if no packet to read */
		if (pcap_dispatch(handle, -1, handle_packet, (u_char *)&user_data) == 0)
		{
			// purge_timedout_probe_request(&shared_data_pcap->to_send->head,
			// 							 &shared_data_pcap->to_send->head,
			// 							 &shared_data_pcap->to_send->tail,
			// 							 &shared_data_pcap->to_send->mut,
			// 							 &shared_data_pcap->to_send->mut);
		}
	}

	return NULL;
}
