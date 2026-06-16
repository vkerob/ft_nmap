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
#include <time.h>
#include <unistd.h>

#define MAX_SENT_RATE_UDP_PER_SEC 5

/*
 * Build a full IP+TCP/UDP packet into `packet`.
 * `src_ip` is the source IP to embed in the IP header and use for checksum
 * computation — pass the real interface IP for normal probes, or a decoy IP
 * when sending spoofed cover packets.
 */
static int build_scan_packets(const t_probe *request, u_char *packet,
							  struct in_addr src_ip, _Atomic u16 *id,
							  u32 *packet_len)
{
	t_ip_pseudo_hdr ip_pseudo_hdr;
	t_datalink_hdr	hdr = { 0 };

	memset(&ip_pseudo_hdr, 0, sizeof(ip_pseudo_hdr));

	char src_ip_buf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &src_ip, src_ip_buf, sizeof(src_ip_buf));

	char dst_ip_buf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &request->target->addr, dst_ip_buf, sizeof(dst_ip_buf));

	t_ip ip_hdr;
	build_ip_header(&ip_hdr, request, src_ip, id);

	if (build_pseudo_ip_header(&ip_pseudo_hdr, dst_ip_buf, src_ip_buf,
							   ip_hdr.ip_p))
		return FAILURE;
	if (request->type == SCAN_SYN || request->type == SCAN_ACK
		|| request->type == SCAN_FIN || request->type == SCAN_XMAS
		|| request->type == SCAN_NULL)
	{
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
		memcpy(packet + sizeof(ip_hdr), &hdr.udp_hdr, sizeof(hdr.udp_hdr));
	else
		memcpy(packet + sizeof(ip_hdr), &hdr.tcp_hdr, sizeof(hdr.tcp_hdr));
	return SUCCESS;
}

static int send_packet(t_socket *socket, const u8 *packet,
					   struct timeval *sent_timestamp, u32 packet_len)
{
	const ssize_t res
		= sendto(socket->sfd, packet, packet_len, 0,
				 (struct sockaddr *)&socket->sin, sizeof(struct sockaddr));

	if (res < 0)
	{
		perror("sendto: ");
		return FAILURE;
	}

	gettimeofday(sent_timestamp, NULL);
	return SUCCESS;
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

	if (init_socket(&tcp_socket, IPPROTO_TCP))
		return NULL;
	if (init_socket(&udp_socket, IPPROTO_UDP))
	{
		close(tcp_socket.sfd);
		return NULL;
	}
	memset(packet, 0, sizeof(packet));
	tcp_socket.sin.sin_family = AF_INET;
	udp_socket.sin.sin_family = AF_INET;

	while (g_stop != 1)
	{
		request = NULL;
		pthread_mutex_lock(&shared_data->to_send.safe_mut.mutex);
		if (!shared_data->to_send.tail)
		{
			/* Queue empty: sleep on the condvar instead of busy-waiting.
			 * A timed wait lets us re-check g_stop periodically even if no
			 * producer signals us (e.g. shutdown set from a signal handler,
			 * which cannot safely broadcast a condvar). */
			struct timespec ts;
			clock_gettime(CLOCK_REALTIME, &ts);
			ts.tv_nsec += 50 * 1000 * 1000; // 50 ms
			if (ts.tv_nsec >= 1000000000L)
			{
				ts.tv_sec += 1;
				ts.tv_nsec -= 1000000000L;
			}
			pthread_cond_timedwait(&shared_data->to_send.cond,
								   &shared_data->to_send.safe_mut.mutex, &ts);
			pthread_mutex_unlock(&shared_data->to_send.safe_mut.mutex);
			continue;
		}
		pop_probe_request(&shared_data->to_send.head,
						  &shared_data->to_send.tail, &request);
		shared_data->to_send.nb_probe--;
		pthread_mutex_unlock(&shared_data->to_send.safe_mut.mutex);
		if (request->type == SCAN_UDP)
		{

			struct timeval now;
			gettimeofday(&now, NULL);
			pthread_mutex_lock(&request->target->mutex);
			struct timeval last = request->target->last_udp_sent;
			pthread_mutex_unlock(&request->target->mutex);

			if (last.tv_sec != 0 || last.tv_usec != 0)
			{
				double elapsed_time_sec = (now.tv_sec - last.tv_sec)
										  + (now.tv_usec - last.tv_usec) / 1e6;

				/* Elapsed time between two consecutive udp probe to say below
				   th max sending rate per second */
				double gap = 1.0 / MAX_SENT_RATE_UDP_PER_SEC;
				double sleep_time = gap - elapsed_time_sec;
				if (sleep_time > 0)
				{
					struct timespec ts = {
						.tv_sec = (time_t)sleep_time,
						.tv_nsec
						= (long)((sleep_time - (time_t)sleep_time) * 1e9),
					};
					nanosleep(&ts, NULL);
				}
			}
		}

		// Compute relative timestamp once for the whole probe (decoys + real)
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

		struct in_addr send_list[MAX_DECOYS + 1];
		u8			   send_count = 0;
		bool		   has_me = false;

		if (shared_data->args && HAS(shared_data->args->flags, F_DECOY))
		{
			for (u8 i = 0; i < shared_data->args->decoy_count; i++)
			{
				send_list[send_count++] = shared_data->args->decoys[i];
				if (shared_data->args->decoys[i].s_addr == INADDR_ANY)
					has_me = true;
			}
		}
		if (!has_me)
			send_list[send_count++] = (struct in_addr){ .s_addr = INADDR_ANY };

		u8	 iface_idx = request->target->iface_info->iface_index;
		bool tracked
			= false; // true once the real probe lives in the sent queue

		for (u8 i = 0; i < send_count; i++)
		{
			bool		   is_me = (send_list[i].s_addr == INADDR_ANY);
			struct in_addr src
				= is_me ? request->target->iface_info->ip_addr : send_list[i];

			memset(packet, 0, sizeof(packet));
			u32 packet_len = 0;
			if (build_scan_packets(request, packet, src, &shared_data->id,
								   &packet_len))
			{
				/* Header build failed (bad address): skip this source.
				 * The real probe will simply time out and be retried. */
				continue;
			}

			t_datalink_hdr datalink_hdr = { 0 };
			if (request->type == SCAN_UDP)
				datalink_hdr.udp_hdr
					= *(t_udp_hdr *)(packet + packet_len - sizeof(t_udp_hdr));
			else
				datalink_hdr.tcp_hdr
					= *(t_tcp_hdr *)(packet + packet_len - sizeof(t_tcp_hdr));

			used_socket = (request->type == SCAN_UDP) ? udp_socket : tcp_socket;
			used_socket.sin.sin_addr = request->target->addr;
			used_socket.sin.sin_port = htons(request->port);

			// Only the real packet (ME) is tracked in the sent queue
			if (is_me)
			{
				pthread_mutex_lock(
					&shared_data->sent[iface_idx].safe_mut.mutex);
				if (add_to_probe_queue(&shared_data->sent[iface_idx].head,
									   &shared_data->sent[iface_idx].tail,
									   request, sent_timestamp))
				{
					pthread_mutex_unlock(
						&shared_data->sent[iface_idx].safe_mut.mutex);
					break; // skip remaining decoys for this probe too
				}
				shared_data->sent[iface_idx].nb_probe++;
				tracked = true;
			}

			t_ip *ip_hdr = (t_ip *)packet;
			if (HAS(shared_data->args->flags, F_PACKET_TRACE))
			{
				if (print_debug_packet_send(request, &relative_sent_time,
											&datalink_hdr, ip_hdr, !is_me))
				{
					if (is_me)
						pthread_mutex_unlock(
							&shared_data->sent[iface_idx].safe_mut.mutex);
					close_sockets(&udp_socket, &tcp_socket);
					return NULL;
				}
			}

			if (send_packet(&used_socket, packet, &sent_timestamp, packet_len)
				&& is_me)
			{
				LOG("ft_nmap: failed to send packet to %s\n",
					inet_ntoa(request->target->addr));
			}

			if (is_me && request->type == SCAN_UDP)
			{
				pthread_mutex_lock(&request->target->mutex);
				gettimeofday(&request->target->last_udp_sent, NULL);
				pthread_mutex_unlock(&request->target->mutex);
			}

			if (is_me)
				pthread_mutex_unlock(
					&shared_data->sent[iface_idx].safe_mut.mutex);
		}

		/* The probe was popped from to_send but never made it into the sent
		 * queue (build/add failure): it will never get a response, so resolve
		 * it now to keep the outstanding counter accurate and avoid a leak. */
		if (!tracked)
		{
			atomic_fetch_sub(&shared_data->outstanding, 1);
			free(request);
		}
	}
	close_sockets(&udp_socket, &tcp_socket);
	return NULL;
}
