#include "send.h"
#include "protocols.h"
#include "shared.h"
#include "typesdef.h"
#include "socket.h"
#include "ip.h"
#include "udp.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>


static void build_scan_packets(t_probe_request *request, u_char *packet,
							   t_shared_data *shared_data)
{
	// struct ether_header	eth_hdr;
	t_ip_pseudo_hdr		ip_pseudo_hdr;
	// struct ip			ip_hdr;
	t_datalink_hdr	hdr = { 0 };

	memset(&ip_pseudo_hdr, 0, sizeof(ip_pseudo_hdr));

	// if (shared_data->gateway_mac[0] != 0)
		// build_ethernet_header(&eth_hdr);

	// build_ip_header(&ip_hdr, request, shared_data->source_ip, &shared_data->id);

	// Use to compute the tcp checksum
	build_pseudo_ip_header(&ip_pseudo_hdr, request->target.ip, shared_data->source_ip);

	if (request->type == SCAN_SYN || request->type == SCAN_ACK
		|| request->type == SCAN_FIN || request->type == SCAN_XMAS
		|| request->type == SCAN_NULL)
	{
		// assemble full packet
		build_tcp_header(&hdr.tcp_hdr, request->target.port,
						 &shared_data->base_port);
		calculate_tcp_checksum(&ip_pseudo_hdr, &hdr.tcp_hdr);
	}
	else if (request->type == SCAN_UDP)
	{
		// build UDP header
		build_udp_header(&hdr.udp_hdr, request->target.port);
	}
	//TEMPORARY

	memcpy(packet, &hdr.tcp_hdr, sizeof(hdr.tcp_hdr));
	(void)packet;
	// assemble_full_packet(packet, &eth_hdr, &ip_hdr, &tcp_hdr, &udp_hdr);
}

static bool send_packet(t_socket *socket, u8 *packet)
{
	if (sendto(
			socket->sfd,
			packet,
			sizeof(struct tcphdr),
			0,
			(struct sockaddr *)&socket->sin,
			sizeof(struct sockaddr)
		) < 0)
	{
		perror("sendto: ");
		return false;
	}
	return true;
}

void	*send_routine(void *arg)
{
	t_shared_data		*shared_data = (t_shared_data *)arg;
	u8							packet[4096];
	t_socket				socket;
	t_probe_request	*popped_request = NULL;

	init_socket(&socket);
	memset(packet, 0, sizeof(packet));
	socket.sin.sin_family = AF_INET;
	while (shared_data->nb_probe_requests > 0)
	{
		pthread_mutex_lock(&shared_data->mutex);
		if (shared_data->request_list_tail){
			pop_probe_request(
				&shared_data->request_list_head,
				shared_data->request_list_tail,
				&popped_request);
		}
		else{
			return NULL;
		}
		shared_data->nb_probe_requests--;
		pthread_mutex_unlock(&shared_data->mutex);
		inet_aton(popped_request->target.ip, &socket.sin.sin_addr);
		build_scan_packets(popped_request, packet, shared_data);

		socket.sin.sin_port = htons(popped_request->target.port);

		if (!send_packet(&socket, packet)){
			//TODO: handle this case
			return NULL;
		}

		free(popped_request);
	}
	return NULL;
}
