#include "args.h"
#include "capture.h"
#include "debug.h"
#include "ethernet.h"
#include "icmp.h"
#include "ip.h"
#include "my_signal.h"
#include "protocols.h"
#include "request.h"
#include "scan.h"
#include "shared.h"
#include "tcp.h"
#include "udp.h"

#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool handle_ip_protocol(t_probe_queue *sent_list, t_ip *ip_hdr,
							   bpf_u_int32	   l3_caplen,
							   struct timeval *relative_recv_time, u16 flags)
{
	const u8	  *protocol_hdr;
	t_datalink_hdr datalink_hdr = { 0 };
	size_t		   ip_hlen;
	size_t		   l4_len;

	// print_debug_ip_header(ip_hdr);
	if (l3_caplen < sizeof(struct ip))
		return true;

	ip_hlen = (size_t)ip_hdr->ip_hl * 4;
	if (ip_hlen < sizeof(struct ip) || l3_caplen < ip_hlen)
		return true;

	protocol_hdr = (const u8 *)ip_hdr + ip_hlen;
	l4_len = l3_caplen - ip_hlen;

	u16			   source_port;
	t_datalink_hdr nested_datalink_header = { 0 };
	t_ip		  *nested_ip_header = NULL;

	switch (ip_hdr->ip_p)
	{
	case IPPROTO_TCP:
		if (l4_len < sizeof(struct tcphdr))
			return true;
		datalink_hdr.tcp_hdr = *(const struct tcphdr *)protocol_hdr;
		// identify response packet
		// handle if it's the response packet in sent queue
		source_port = ntohs(datalink_hdr.tcp_hdr.th_sport);
		t_scan_type scan_type
			= determine_tcp_scan_type(ntohs(datalink_hdr.tcp_hdr.th_dport));
		handle_tcp_response(sent_list, datalink_hdr.tcp_hdr.th_flags, scan_type,
							source_port, ip_hdr->ip_src);
		break;

	case IPPROTO_UDP:
		if (l4_len < sizeof(struct udphdr))
			return false;
		source_port = ntohs(datalink_hdr.udp_hdr.uh_sport);
		datalink_hdr.udp_hdr = *(const struct udphdr *)protocol_hdr;
		handle_udp_response(sent_list, source_port, ip_hdr->ip_src);
		break;

	case IPPROTO_ICMP:
		if (l4_len < sizeof(t_icmp_hdr))
			return false;
		datalink_hdr.icmp_hdr = *(const t_icmp_hdr *)protocol_hdr;

		// 8 bytes is the size of icmp header
		nested_ip_header
			= (t_ip *)((u8 *)ip_hdr + ip_hlen + sizeof(t_icmp_hdr));

		// print_debug_ip_header(nested_ip_header);

		int ip2_hlen = (size_t)nested_ip_header->ip_hl * 4;
		u8 *datalink_header = (u8 *)nested_ip_header + ip2_hlen;

		switch (nested_ip_header->ip_p)
		{
		case IPPROTO_TCP:

			nested_datalink_header.tcp_hdr = *(t_tcp_hdr *)datalink_header;
			source_port = ntohs(nested_datalink_header.tcp_hdr.th_dport);
			// print_debug_tcp_header(&nested_datalink_header.tcp_hdr);
			t_scan_type scan_type = determine_tcp_scan_type(
				ntohs(nested_datalink_header.tcp_hdr.th_dport));
			handle_icmp_response(sent_list, source_port, ip_hdr->ip_src,
								 datalink_hdr.icmp_hdr, scan_type, IPPROTO_TCP);
			break;
		case IPPROTO_UDP:
			nested_datalink_header.udp_hdr = *(t_udp_hdr *)datalink_header;
			source_port = ntohs(nested_datalink_header.udp_hdr.uh_dport);
			handle_icmp_response(sent_list, source_port, ip_hdr->ip_src,
								 datalink_hdr.icmp_hdr, SCAN_UDP, IPPROTO_UDP);
			break;
		default:
			return true;
		}
		break;

	default:
		return true;
	}
	// When we receive an ICMP response there is the header which mimics the one
	// we send in our probe following the ICMP header: [IP Header + UDP/TCP
	// Header] which contains the error code of why it fails to returns us a
	// proper UPD / TCP response instead

	if (HAS(flags, F_PACKET_TRACE))
	{
		return print_debug_packet_recv(ip_hdr, &datalink_hdr,
									   &nested_datalink_header,
									   nested_ip_header, relative_recv_time);
	}
	return false;
}

static bool parse_datalink_layer(pcap_t *handle, t_probe_queue *sent_list,
								 const u_char *packet, bpf_u_int32 caplen,
								 struct timeval *relative_recv_time,
								 const u16		 flags)
{
	const int	  datalink_type = pcap_datalink(handle);
	const u_char *ip_start = NULL;
	bpf_u_int32	  l3_caplen = 0;

	// print_debug_datalink_type(datalink_type);

	switch (datalink_type)
	{
	case DLT_EN10MB:
	{
		// [6 dst MAC][6 src MAC][2 EtherType] + IP...
		const size_t l2_len = sizeof(struct ether_header);
		if (caplen < l2_len + sizeof(struct ip))
			return false;

		struct ether_header *eth_header = (struct ether_header *)packet;
		// print_debug_ethernet_type(ntohs(eth_header->ether_type));
		// print_debug_ethernet_header(eth_header);
		if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
			return false;

		ip_start = packet + l2_len;
		l3_caplen = caplen - (bpf_u_int32)l2_len;
		break;
	}
	case DLT_NULL:
	{
		// [4 bytes AF_family in host byte order] + IP...
		const bpf_u_int32 l2_len = 4;
		if (caplen < l2_len + sizeof(struct ip))
			return false;

		uint32_t af_type;
		memcpy(&af_type, packet, 4); // no ntohl: already in host byte order
		if (af_type != AF_INET)
			return false;

		ip_start = packet + l2_len;
		l3_caplen = caplen - l2_len;
		break;
	}
	case DLT_RAW:
		// no datalink header, packet starts directly at the IP header
		if (caplen < sizeof(struct ip))
			return false;

		ip_start = packet;
		l3_caplen = caplen;
		break;

	default:
		return false;
	}

	return handle_ip_protocol(sent_list, (t_ip *)ip_start, l3_caplen,
							  relative_recv_time, flags);
}

void handle_packet(u8 *args, const struct pcap_pkthdr *header,
				   const u_char *packet)
{
	// pthread_t phid = pthread_self();

	// print_debug_thread_startup(phid, __FUNCTION__);
	const t_pcap_user_data *user_data = (t_pcap_user_data *)args;
	const t_receiver_data  *receiver_data = user_data->receiver_data;

	(void)receiver_data;

	t_probe_queue		 *sent_list = user_data->receiver_data->sent;
	const t_program_info *program_info = receiver_data->program_info;

	struct timeval recv_timestamp;
	gettimeofday(&recv_timestamp, NULL);

	long seconds_elapsed = recv_timestamp.tv_sec - program_info->start.tv_sec;
	long microseconds_elapsed
		= recv_timestamp.tv_usec - program_info->start.tv_usec;

	if (microseconds_elapsed < 0)
	{
		seconds_elapsed--;
		microseconds_elapsed += 1000000;
	}

	struct timeval relative_recv_time
		= { .tv_sec = seconds_elapsed, .tv_usec = microseconds_elapsed };

	// print_debug_packet_start();
	parse_datalink_layer(user_data->handle, sent_list, packet, header->caplen,
						 &relative_recv_time, receiver_data->args->flags);
	// print_debug_thread_leave(phid, __FUNCTION__);
}

bool purge_timedout_probe_request(t_probe_queue *sent, t_probe_queue *to_send)
{
	t_probe *next = NULL;

	// pthread_t phid = pthread_self();

	//	print_debug_thread_startup(phid, __FUNCTION__);
	pthread_mutex_lock(&sent->mut);
	t_probe *tmp = sent->head;
	while (tmp)
	{
		struct timeval current_time;
		gettimeofday(&current_time, NULL);

		long seconds_elapsed = current_time.tv_sec - tmp->timestamp.tv_sec;
		long microseconds_elapsed
			= current_time.tv_usec - tmp->timestamp.tv_usec;

		if (microseconds_elapsed < 0)
		{
			seconds_elapsed--;
			microseconds_elapsed += 1000000;
		}
		double time_elapsed = seconds_elapsed + (microseconds_elapsed / 1e6);
		// printf("elapsed time seconds: %lu microseconds: %lu\n",
		// seconds_elapsed, 	   microseconds_elapsed); printf("time elapsed:
		// %f\n", time_elapsed);

		next = tmp->next;

		// print_debug_probe_request(tmp);

		if (time_elapsed > TIMEOUT_DELAY)
		{
			// print_debug_probe_exceed_timeout(tmp, &current_time,
			// seconds_elapsed);

			// Erase tmp from the sent list
			erase_reference_to_node(&sent->head, &sent->tail, tmp,
									&sent->nb_probe);
			// Update retries and reinject in to_send probe queue

			tmp->retries++;

			if (tmp->retries > MAX_SCAN_RETRIES)
			{
				const int index
					= tmp->target->port_list.port_map[tmp->port];
				t_port *port
					= &tmp->target->port_list.port_map_rev[tmp->type][index];
				switch (tmp->type)
				{
				case SCAN_SYN:
				case SCAN_ACK:
					port->port_state = FILTERED;
					set_port_state_reason(port, NO_RESPONSE);
					break;
				case SCAN_FIN:
				case SCAN_NULL:
				case SCAN_XMAS:
				case SCAN_UDP:
					port->port_state = OPEN_FILTERED;
					set_port_state_reason(port, NO_RESPONSE);
					break;
				default:
					break;
				}

				free(tmp);
				tmp = next;
				continue;
			}
			memset(&tmp->timestamp, 0, sizeof(struct timeval));
			pthread_mutex_lock(&to_send->mut);
			// update next of current tail or head if list is empty
			if (to_send->tail)
			{
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
		// else
		//{
		//	sync_printf(ANSI_BOLD ANSI_COLOR_BLUE "Probe %d did not timeout\n"
		// ANSI_COLOR_RESET, tmp->id);
		// }
		tmp = next;
	}
	pthread_mutex_unlock(&sent->mut);
	//	print_debug_thread_leave(phid, __FUNCTION__);
	return false;
}

void *capture_routine(void *arg)
{
	// pthread_t phid = pthread_self();
	// print_debug_thread_startup(phid, __FUNCTION__);

	t_receiver_data *receiver_data = arg;
	// TODO: change this
	pcap_t *handle = receiver_data->handle;

	char errbuf[PCAP_ERRBUF_SIZE];

	// sync_printf("test %u\n", pthread_self());

	// const struct timeval *timeout = pcap_get_required_select_timeout(handle);
	// if (timeout == NULL)
	// {
	// 	LOG("timeout not required\n");
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
		LOG("pcap_setnonblock: Capture handle is not activated\n");
		return NULL;
	case PCAP_ERROR:
		LOG("pcap_setnonblock: %s\n", errbuf);
		return NULL;
	default:
		break;
	}

	while (g_stop != 1
		   && (receiver_data->sent->nb_probe != 0
			   || receiver_data->to_send->nb_probe != 0))
	{
		t_pcap_user_data user_data
			= { .handle = handle, .receiver_data = receiver_data };
		/* Returns 0 if no packet to read */
		if (pcap_dispatch(handle, -1, handle_packet, (u_char *)&user_data) == 0)
		{
			purge_timedout_probe_request(receiver_data->sent,
										 receiver_data->to_send);
		}
	}
	// print_debug_thread_leave(phid, __FUNCTION__);
	return NULL;
}
