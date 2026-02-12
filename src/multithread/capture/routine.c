#include "capture.h"
#include "debug.h"
#include "ethernet.h"
#include "icmp.h"
#include "ip.h"
#include "my_signal.h"
#include "probe_request.h"
#include "protocols.h"
#include "sll.h"
#include "tcp.h"
#include "udp.h"

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

void handle_ip_protocol(t_ip *ip_hdr, t_datalink_hdr *hdr)
{
	void *protocol_hdr;

	protocol_hdr = (void *)((u8 *)ip_hdr + ip_hdr->ip_hl * 4);

	// if (find_corresponding_target(targets, targets_count, &ip_hdr->ip_src,
	// target))
	// {
	// 	//TODO: handle this case
	// 	return ;
	// }
	print_debug_protocol(ip_hdr->ip_p);

	switch (ip_hdr->ip_p)
	{
	case IPPROTO_TCP:
	{
		hdr->tcp_hdr = *(struct tcphdr *)protocol_hdr;
		print_debug_tcp_header(&hdr->tcp_hdr);
		/* PROTO_TCP is our enum with the right integer value because
						we use it as an index after */
		// handle_tcp_protocol(target, &hdr->tcp_hdr);
		break;
	}
	case IPPROTO_ICMP:
	{
		// struct tcphdr *tcp_hdr = (struct tcphdr *)protocol_hdr;
		// handle_icmp_protocol(&target, tcp_hdr);
		// struct icmphdr *icmp_hdr = (struct icmphdr *)protocol_hdr;
		// print_debug_icmp_header(icmp_hdr);
		break;
	}
	case IPPROTO_UDP:
	{
		// struct udphdr *udp_hdr = (struct udphdr *)protocol_hdr;
		// print_debug_udp_header(udp_hdr);
		break;
	}
	default:
		break;
	}
}

static void handle_with_ethernet(const u_char *packet, t_ip *ip_hdr,
								 t_datalink_hdr *hdr)
{
	struct ether_header *eth_header = (struct ether_header *)packet;
	print_debug_ethernet_type(ntohs(eth_header->ether_type));

	if (ntohs(eth_header->ether_type) == ETHERTYPE_IP)
	{
		ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
		print_debug_ethernet_header(eth_header);
		print_debug_ip_header(ip_hdr);
		handle_ip_protocol(ip_hdr, hdr);
	}
}

static void parse_datalink_layer(const u_char *packet, t_ip *ip_hdr,
								 t_datalink_hdr *datalink_hdr, pcap_t *handle)
{
	int datalink_type = pcap_datalink(handle);
	print_debug_datalink_type(datalink_type);

	switch (datalink_type)
	{
	case DLT_EN10MB:
		printf("DLT_EN10MB\n");
		handle_with_ethernet(packet, ip_hdr, datalink_hdr);
		break;
		// case DLT_LINUX_SLL:
		// 	printf("DLT_LINUX_SLL\n");
		// 	handle_with_linux_sll(packet);
		// 	break;
		// case DLT_RAW:
		// 	printf("DLT_RAW\n");
		// 	// handle_with_raw_ip(packet, targets);
		// 	break;
		// case DLT_NULL:
		// 	printf("DLT_NULL\n");
		// 	handle_with_null_loopback(packet);
		break;
	default:
		printf("default\n");
		break;
	}
}

void handle_packet(u_char *args, const struct pcap_pkthdr *header,
				   const u_char *packet)
{
	print_debug_packet_start();
	(void)args;
	(void)header;
	t_pcap_user_data		  *user_data = (t_pcap_user_data *)args;
	pcap_t					  *handle = user_data->handle;
	t_shared_data_pcap_thread *shared_data_probe = user_data->shared_data_probe;
	t_ip					   ip_hdr;
	t_datalink_hdr			   hdr;
	// t_target				   target;

	(void)handle;
	(void)shared_data_probe;
	(void)packet;
	parse_datalink_layer(packet, &ip_hdr, &hdr, handle);
	// find_corresponding_target(shared_data_probe->targets,
	// shared_data_probe->target_count, &ip_hdr.ip_src, &target);
	print_debug_packet_end();

	// t_probe_request_sent *tmp = *shared_data_probe->pending_request_head;
	// while (tmp)
	// {
	// 	if (strcmp(tmp->request->target.ip, target.ip) == 0)
	// 	{
	// 		// TODO:
	// 		//
	// pthread_mutex_lock(&shared_data_probe->pending_request_list_mut[0]); is
	// 		// hardcoded
	// 		pthread_mutex_lock(&shared_data_probe->pending_request_list_mut[0]);
	// 		if (tmp->prev)
	// 		{
	// 			tmp->prev->next = tmp->next;
	// 			tmp->next->prev = tmp->prev;
	// 			t_probe_request_sent *save = tmp->next;
	// 			free(tmp);
	// 			tmp = save;
	// 		}
	// 		pthread_mutex_unlock(&shared_data_probe->pending_request_list_mut[0]);
	// 	}
	// 	tmp = tmp->next;
	// }
}

static void
purge_timedout_probe_request(t_probe_request **head_pending_list,
							 t_probe_request **head, t_probe_request **tail,
							 pthread_mutex_t *pending_request_list_mut,
							 pthread_mutex_t *request_list_mut)
{
	time_t			 now;
	t_probe_request *tmp = *head_pending_list;

	pthread_mutex_lock(pending_request_list_mut);
	while (tmp)
	{
		now = time(NULL);
		unsigned long seconds_elapsed
			= (unsigned long)difftime(tmp->timestamp, now);

		if (seconds_elapsed > TIMEOUT_DELAY_SECONDS)
		{
			// Pop tmp from the pending list
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
				*head_pending_list = tmp->next;
			}
			// Update retries and reinject in probe request list
			if (tmp->retries < MAX_SCAN_RETRIES)
			{
				tmp->retries += 1;
				tmp->timestamp = 0;
			}
			pthread_mutex_lock(request_list_mut);
			if (*tail)
			{
				(*tail)->next = tmp;
			}
			else
			{
				*head = tmp;
			}
			// update tail to new request
			*tail = tmp;
			pthread_mutex_unlock(request_list_mut);
			// free probe_request_sent object
		}
		tmp = tmp->next;
	}
	pthread_mutex_unlock(pending_request_list_mut);
}

void *receive_routine(void *arg)
{
	t_shared_data_pcap_thread *shared_data_probe
		= (t_shared_data_pcap_thread *)arg;
	// TODO: change this
	pcap_t *handle = shared_data_probe->handle;

	char errbuf[PCAP_ERRBUF_SIZE];
	int	 ret;

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
			= { .handle = handle, .shared_data_probe = shared_data_probe };
		/* Returns 0 if no packet to read */
		if (pcap_dispatch(handle, -1, handle_packet, (u_char *)&user_data) == 0)
		{

			purge_timedout_probe_request(
				&shared_data_probe->pending_request_head,
				&shared_data_probe->request_list_head,
				&shared_data_probe->request_list_tail,
				&shared_data_probe->pending_request_list_mut,
				&shared_data_probe->request_list_mut);
		}
	}

	return NULL;
}
