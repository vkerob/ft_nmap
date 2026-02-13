#include "ip.h"
#include "protocols.h"
#include "send.h"
#include "shared.h"
#include "socket.h"
#include "typesdef.h"
#include "udp.h"

#include <pthread.h>
#include <string.h>

static void build_scan_packets(t_request *request, u_char *packet)
{
	// struct ether_header	eth_hdr;
	t_ip_pseudo_hdr ip_pseudo_hdr;
	// struct ip			ip_hdr;
	t_datalink_hdr hdr = { 0 };

	memset(&ip_pseudo_hdr, 0, sizeof(ip_pseudo_hdr));

	// if (shared_data_probe->gateway_mac[0] != 0)
	// build_ethernet_header(&eth_hdr);

	// build_ip_header(&ip_hdr, request, shared_data_probe->source_ip,
	// &shared_data_probe->id);

	// Use to compute the tcp checksum
	const char *src_ip = inet_ntoa(request->iface_info.ip_addr);
	build_pseudo_ip_header(&ip_pseudo_hdr, inet_ntoa(request->target.ip_addr),
						   src_ip);

	if (request->type == SCAN_SYN || request->type == SCAN_ACK
		|| request->type == SCAN_FIN || request->type == SCAN_XMAS
		|| request->type == SCAN_NULL)
	{
		// assemble full packet
		build_tcp_header(&hdr.tcp_hdr, request->target.port, request->type);
		calculate_tcp_checksum(&ip_pseudo_hdr, &hdr.tcp_hdr);
	}
	else if (request->type == SCAN_UDP)
	{
		// build UDP header
		build_udp_header(&hdr.udp_hdr, request->target.port);
	}
	// TEMPORARY

	memcpy(packet, &hdr.tcp_hdr, sizeof(hdr.tcp_hdr));
	(void)packet;
	// assemble_full_packet(packet, &eth_hdr, &ip_hdr, &tcp_hdr, &udp_hdr);
}

static bool send_packet(t_socket *socket, u8 *packet, time_t *sent_timestamp)
{
	if (sendto(socket->sfd, packet, sizeof(struct tcphdr), 0,
			   (struct sockaddr *)&socket->sin, sizeof(struct sockaddr))
		< 0)
	{
		perror("sendto: ");
		return true;
	}
	time(sent_timestamp);
	return false;
}

void *send_routine(void *arg)
{
	t_shared_data_probe *shared_data_probe = (t_shared_data_probe *)arg;
	u8					 packet[4096];
	t_socket			 tcp_socket;
	t_socket			 udp_socket;
	t_socket			 used_socket;
	t_request			*request = NULL;
	time_t				 sent_timestamp;

	if (init_socket(&tcp_socket, IPPROTO_TCP)
		|| init_socket(&udp_socket, IPPROTO_UDP))
	{
		return NULL;
	}
	memset(packet, 0, sizeof(packet));
	tcp_socket.sin.sin_family = AF_INET;
	udp_socket.sin.sin_family = AF_INET;

	while (shared_data_probe->probe_request_list.nb_probe_requests > 0)
	{
		// t_datalink_hdr	*hdr = NULL;
		pthread_mutex_lock(&shared_data_probe->probe_request_list.mut);
		if (shared_data_probe->probe_request_list.tail)
		{
			pop_probe_request(&shared_data_probe->probe_request_list.head,
							  &shared_data_probe->probe_request_list.tail,
							  &request);
		}
		else
		{
			pthread_mutex_unlock(&shared_data_probe->probe_request_list.mut);
			return NULL;
		}
		shared_data_probe->probe_request_list.nb_probe_requests--;
		pthread_mutex_unlock(&shared_data_probe->probe_request_list.mut);
		if (request->type == SCAN_UDP)
		{
			used_socket = udp_socket;
		}
		else
		{
			used_socket = tcp_socket;
		}

		inet_aton(inet_ntoa(request->target.ip_addr), &used_socket.sin.sin_addr);
		build_scan_packets(request, packet);

		used_socket.sin.sin_port = htons(request->target.port);

		if (request->type == SCAN_UDP)
		{
			t_udp_hdr *udp_hdr = (t_udp_hdr *)packet;
			// print_debug_udp_header(udp_hdr);
			(void)udp_hdr;
		}
		else
		{
			t_tcp_hdr *tcp_hdr = (t_tcp_hdr *)packet;
			// print_debug_tcp_header(tcp_hdr);
			(void)tcp_hdr;
		}

		if (send_packet(&used_socket, packet, &sent_timestamp))
		{
			fprintf(stderr, "ft_nmap: failed to send packet to %s\n",
					inet_ntoa(request->target.ip_addr));
			return NULL;
		}

		pthread_mutex_lock(
			&shared_data_probe
				 ->pending_request_list[request->iface_info.iface_index]
				 .mut);
		if (update_pending_probe_request_list(
				&(shared_data_probe
					  ->pending_request_list[request->iface_info.iface_index]
					  .head),
				&shared_data_probe
					 ->pending_request_list[request->iface_info.iface_index]
					 .tail,
				request, sent_timestamp))
		{
			pthread_mutex_unlock(
				&shared_data_probe
					 ->pending_request_list[request->iface_info.iface_index]
					 .mut);
			return NULL;
		}
		pthread_mutex_unlock(
			&shared_data_probe
				 ->pending_request_list[request->iface_info.iface_index]
				 .mut);
	}
	return NULL;
}
