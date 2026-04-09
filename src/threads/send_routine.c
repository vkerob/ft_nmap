#include "debug.h"
#include "ip.h"
#include "my_signal.h"
#include "protocols.h"
#include "send.h"
#include "shared.h"
#include "socket.h"
#include "typesdef.h"
#include "udp.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>

static void build_scan_packets(const t_probe *request, u_char *packet,
							   _Atomic u16 *id, u32 *packet_len)
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

	// Use to compute the tcp and udp checksum
	char src_ip_buf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &request->target->iface_info->ip_addr, src_ip_buf,
			  sizeof(src_ip_buf));
	char dst_ip_buf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &request->target->addr, dst_ip_buf, sizeof(dst_ip_buf));

	t_ip ip_hdr;
	build_ip_header(&ip_hdr, request, id);

	build_pseudo_ip_header(&ip_pseudo_hdr, dst_ip_buf, src_ip_buf, ip_hdr.ip_p);
	if (request->type == SCAN_SYN || request->type == SCAN_ACK
		|| request->type == SCAN_FIN || request->type == SCAN_XMAS
		|| request->type == SCAN_NULL)
	{
		// Assemble full packet
		build_tcp_header(&hdr.tcp_hdr, request->port, request->type);
		calculate_tcp_checksum(&ip_pseudo_hdr, &hdr.tcp_hdr);
		ip_hdr.ip_len += sizeof(t_tcp_hdr);
	}
	else if (request->type == SCAN_UDP)
	{
		build_udp_header(&hdr.udp_hdr, request->port);
		calculate_udp_checksum(&ip_pseudo_hdr, &hdr.udp_hdr);
		ip_hdr.ip_len += sizeof(t_udp_hdr);
	}
	*packet_len = ip_hdr.ip_len;
	ip_hdr.ip_len = htons(ip_hdr.ip_len);
	ip_hdr.ip_sum = calculate_checksum(&ip_hdr, ip_hdr.ip_hl * 4);
#ifdef __APPLE__
	// macOS IP_HDRINCL requires ip_len in host byte order
	ip_hdr.ip_len = ntohs(ip_hdr.ip_len);
#endif

	memcpy(packet, &ip_hdr, sizeof(ip_hdr));
	if (request->type == SCAN_UDP)
	{
		memcpy(packet + sizeof(ip_hdr), &hdr.udp_hdr, sizeof(hdr.udp_hdr));
	}
	else
	{
		memcpy(packet + sizeof(ip_hdr), &hdr.tcp_hdr, sizeof(hdr.tcp_hdr));
	}
	// print_debug_ip_header(&ip_hdr);
	//  assemble_full_packet(packet, &eth_hdr, &ip_hdr, &tcp_hdr, &udp_hdr);
}

static bool send_packet(t_socket *socket, const u8 *packet,
						struct timeval *sent_timestamp, u32 packet_len)
{
	//printf("Sending packet to %s:%u\n", inet_ntoa(socket->sin.sin_addr),
		  //  ntohs(socket->sin.sin_port));
	const ssize_t res
		= sendto(socket->sfd, packet, packet_len, 0,
				 (struct sockaddr *)&socket->sin, sizeof(struct sockaddr));

	if (res < 0)
	{
		perror("sendto: ");
		return true;
	}

	// sync_printf("Number of bytes sent: %d\n", res);
	gettimeofday(sent_timestamp, NULL);
	return false;
}

static void close_sockets(const t_socket *udp_socket,
						  const t_socket *tcp_socket)
{
	close(udp_socket->sfd);
	close(tcp_socket->sfd);
}

void *send_routine(void *arg)
{
	t_shared_data_sender *shared_data = arg;
	u8					  packet[4096];
	t_socket			  tcp_socket;
	t_socket			  udp_socket;
	t_socket			  used_socket;
	t_probe				 *request = NULL;
	struct timeval		  sent_timestamp;
	// pthread_t phid = pthread_self();
	// print_debug_thread_startup(phid, __FUNCTION__);

	if (init_socket(&tcp_socket, IPPROTO_TCP)
		|| init_socket(&udp_socket, IPPROTO_UDP))
	{
		return NULL;
	}
	memset(packet, 0, sizeof(packet));
	tcp_socket.sin.sin_family = AF_INET;
	udp_socket.sin.sin_family = AF_INET;

	while (g_stop != 1)
	{
		request = NULL;
		pthread_mutex_lock(&shared_data->to_send.mut);
		if (shared_data->to_send.tail)
		{
			pop_probe_request(&shared_data->to_send.head,
							  &shared_data->to_send.tail, &request);
		}
		else
		{
			pthread_mutex_unlock(&shared_data->to_send.mut);
			continue;
		}
		pthread_mutex_unlock(&shared_data->to_send.mut);
		if (request->type == SCAN_UDP)
		{
			used_socket = udp_socket;
		}
		else
		{
			used_socket = tcp_socket;
		}
		used_socket.sin.sin_addr = request->target->addr;
		u32 packet_len = 0;
		build_scan_packets(request, packet, &shared_data->id, &packet_len);

		used_socket.sin.sin_port = htons(request->port);
		t_datalink_hdr datalink_hdr = { 0 };

		if (request->type == SCAN_UDP)
		{
			t_udp_hdr *udp_hdr
				= (t_udp_hdr *)(packet + packet_len - (sizeof(t_udp_hdr)));
			// print_debug_udp_header(udp_hdr);
			datalink_hdr.udp_hdr = *udp_hdr;
			(void)udp_hdr;
		}
		else
		{
			t_tcp_hdr *tcp_hdr
				= (t_tcp_hdr *)(packet + packet_len - (sizeof(t_tcp_hdr)));
			// print_debug_tcp_header(tcp_hdr);
			datalink_hdr.tcp_hdr = *tcp_hdr;
			(void)tcp_hdr;
		}

		// Set timestamp now so the sent queue has a valid time reference
		gettimeofday(&sent_timestamp, NULL);

		long seconds_elapsed
			= sent_timestamp.tv_sec - shared_data->program_info->start.tv_sec;

		long microseconds_elapsed
			= sent_timestamp.tv_usec - shared_data->program_info->start.tv_usec;

		if (microseconds_elapsed < 0)
		{
			seconds_elapsed--;
			microseconds_elapsed += 1000000;
		}

		struct timeval relative_sent_time
			= { .tv_sec = seconds_elapsed, .tv_usec = microseconds_elapsed };

		struct timeval tv;

		const int res = gettimeofday(&tv, NULL);
		if (res == -1)
		{
			fprintf(stderr, "ft_nmap: gettimeofday: %s\n", strerror(errno));
			continue;
			// close_sockets(&udp_socket, &tcp_socket);
			// print_debug_thread_leave(phid, __FUNCTION__);
			// return NULL;
		}

		// print_debug_sender_thread_proceed_probe(phid, request, &tv);
		pthread_mutex_lock(
			&shared_data->sent[request->target->iface_info->iface_index].mut);

		if (add_to_probe_queue(
				&(shared_data->sent[request->target->iface_info->iface_index]
					  .head),
				&shared_data->sent[request->target->iface_info->iface_index]
					 .tail,
				request, sent_timestamp))
		{
			pthread_mutex_unlock(
				&shared_data->sent[request->target->iface_info->iface_index]
					 .mut);
			continue;
		}
		//	print_debug_sent_queue_state(
		//		request->target->iface_info->iface_index,
		//		&shared_data->sent[request->target->iface_info->iface_index]);

		shared_data->sent[request->target->iface_info->iface_index].nb_probe++;
		shared_data->to_send.nb_probe--;
		t_ip *ip_hdr = (t_ip *)packet;
		if (HAS(shared_data->flags, F_PACKET_TRACE)) {
			if (print_debug_packet_send(request, &relative_sent_time, &datalink_hdr,
									ip_hdr))
			return NULL;
		}
		if (send_packet(&used_socket, packet, &sent_timestamp, packet_len))
		{
			fprintf(stderr, "ft_nmap: failed to send packet to %s\n",
					inet_ntoa(request->target->addr));
			continue;
		}
		pthread_mutex_unlock(
			&shared_data->sent[request->target->iface_info->iface_index].mut);

		// print_debug_sent_queue_state(
		// 	request->target->iface_info->iface_index,
		// 	&shared_data->sent[request->target->iface_info->iface_index]);
	}
	close_sockets(&udp_socket, &tcp_socket);
	// print_debug_thread_leave(phid, __FUNCTION__);
	return NULL;
}
