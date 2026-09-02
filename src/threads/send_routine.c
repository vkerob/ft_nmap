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

static int build_scan_packets(struct in_addr dst_addr, u16 port,
							  t_scan_type type, u_char *packet,
							  struct in_addr src_ip, _Atomic u16 *id,
							  u32 *packet_len, const u8 *udp_payload,
							  size_t udp_payload_len)
{
	t_ip_pseudo_hdr ip_pseudo_hdr;
	t_datalink_hdr	hdr = { 0 };

	memset(&ip_pseudo_hdr, 0, sizeof(ip_pseudo_hdr));

	char src_ip_buf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &src_ip, src_ip_buf, sizeof(src_ip_buf));

	char dst_ip_buf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &dst_addr, dst_ip_buf, sizeof(dst_ip_buf));

	t_ip ip_hdr;
	build_ip_header(&ip_hdr, type, dst_addr, src_ip, id);

	if (build_pseudo_ip_header(&ip_pseudo_hdr, dst_ip_buf, src_ip_buf,
							   ip_hdr.ip_p) == FAILURE)
		return FAILURE;
	if (type == SCAN_SYN || type == SCAN_ACK || type == SCAN_FIN
		|| type == SCAN_XMAS || type == SCAN_NULL)
	{
		build_tcp_header(&hdr.tcp_hdr, port, type);
		calculate_tcp_checksum(&ip_pseudo_hdr, &hdr.tcp_hdr);
		ip_hdr.ip_len += sizeof(t_tcp_hdr);
	}
	else if (type == SCAN_UDP)
	{
		ip_pseudo_hdr.length
			= htons((u16)(sizeof(t_udp_hdr) + udp_payload_len));
		build_udp_header(&hdr.udp_hdr, port, (u16)udp_payload_len);
		calculate_udp_checksum(&ip_pseudo_hdr, &hdr.udp_hdr, udp_payload,
							   (u16)udp_payload_len);
		ip_hdr.ip_len += sizeof(t_udp_hdr) + udp_payload_len;
	}
	*packet_len = ip_hdr.ip_len;
	ip_hdr.ip_len = htons(ip_hdr.ip_len);
	ip_hdr.ip_sum = calculate_checksum(&ip_hdr, ip_hdr.ip_hl * 4);
#ifdef __APPLE__
	// macOS IP_HDRINCL requires ip_len in host byte order
	ip_hdr.ip_len = ntohs(ip_hdr.ip_len);
#endif

	memcpy(packet, &ip_hdr, sizeof(ip_hdr));
	if (type == SCAN_UDP)
	{
		memcpy(packet + sizeof(ip_hdr), &hdr.udp_hdr, sizeof(hdr.udp_hdr));
		if (udp_payload != NULL && udp_payload_len > 0)
			memcpy(packet + sizeof(ip_hdr) + sizeof(hdr.udp_hdr), udp_payload,
				   udp_payload_len);
	}
	else
		memcpy(packet + sizeof(ip_hdr), &hdr.tcp_hdr, sizeof(hdr.tcp_hdr));
	return SUCCESS;
}

static int send_packet(const t_socket *socket, const u8 *packet,
					   struct timeval *sent_timestamp, u32 packet_len)
{
	const ssize_t res
		= sendto(socket->sfd, packet, packet_len, 0,
				 (const struct sockaddr *)&socket->sin, sizeof(struct sockaddr));

	if (res < 0)
	{
		perror("sendto: ");
		return FAILURE;
	}

	if (gettimeofday(sent_timestamp, NULL) == -1)
	{
		LOG("ft_nmap: gettimeofday failed: %s\n", strerror(errno));
		return FAILURE;
	}
	return SUCCESS;
}

static void close_sockets(const t_socket *udp_socket,
						  const t_socket *tcp_socket)
{
	close(udp_socket->sfd);
	close(tcp_socket->sfd);
}

static void udp_rate_limit(t_target *target)
{
	const long	   gap_us = 1000000L / MAX_SENT_RATE_UDP_PER_SEC;
	struct timeval now;
	struct timeval slot;

	pthread_mutex_lock(&target->mutex);
	gettimeofday(&now, NULL);
	if (target->last_udp_sent.tv_sec == 0 && target->last_udp_sent.tv_usec == 0)
	{
		slot = now; // first UDP packet to this target: send immediately
	}
	else
	{
		slot = target->last_udp_sent; // earliest allowed = last slot + gap
		slot.tv_usec += gap_us;
		if (slot.tv_usec >= 1000000)
		{
			slot.tv_sec += slot.tv_usec / 1000000;
			slot.tv_usec %= 1000000;
		}
		if (slot.tv_sec < now.tv_sec
			|| (slot.tv_sec == now.tv_sec && slot.tv_usec < now.tv_usec))
			slot = now; // last send is already older than the gap: send now
	}
	target->last_udp_sent = slot; // reserve this slot before releasing the lock
	pthread_mutex_unlock(&target->mutex);

	long sec = slot.tv_sec - now.tv_sec;
	long usec = slot.tv_usec - now.tv_usec;
	if (usec < 0)
	{
		sec--;
		usec += 1000000;
	}
	if (sec > 0 || (sec == 0 && usec > 0))
	{
		struct timespec ts = { .tv_sec = sec, .tv_nsec = usec * 1000 };
		nanosleep(&ts, NULL);
	}
}
static void 	compute_relative_timestamp(struct timeval *relative_ts, 
	struct timeval *ts_end, struct timeval *ts_start)
{

		long seconds_elapsed
			= ts_end->tv_sec - ts_start->tv_sec;
		long microseconds_elapsed
			= ts_end->tv_usec - ts_start->tv_usec;
		if (microseconds_elapsed < 0)
		{
			seconds_elapsed--;
			microseconds_elapsed += 1000000;
		}
		relative_ts->tv_sec = seconds_elapsed;
		relative_ts->tv_usec = microseconds_elapsed;
}

void *send_routine(void *arg)
{
	t_shared_data_sender *shared_data = arg;
	u8					  packet[4096];
	t_socket			  tcp_socket;
	t_socket			  udp_socket;
	t_socket			  used_socket;
	t_probe				 *request = NULL;
	struct timeval sent_timestamp = { 0 };
	struct timeval relative_sent_timestamp = { 0 };


	if (init_socket(&tcp_socket, IPPROTO_TCP) == FAILURE)
		return NULL;
	if (init_socket(&udp_socket, IPPROTO_UDP) == FAILURE)
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
			/* Right before the sleep the mutex is unlock, right before the threads 
			 * wakes up pthread_cond_timedwait re-lock the mutex.
			 * The sleeping threads will either be woke up when pthread_cond_signal is called 
			 * in the capture routine when a probe is added back or if it reach the final time.
			*/
			pthread_cond_timedwait(&shared_data->to_send.cond,
								   &shared_data->to_send.safe_mut.mutex, &ts);
			pthread_mutex_unlock(&shared_data->to_send.safe_mut.mutex);
			continue;
		}
		pop_probe_request(&shared_data->to_send.head,
						  &shared_data->to_send.tail, &request);
		shared_data->to_send.nb_probe--;
		pthread_mutex_unlock(&shared_data->to_send.safe_mut.mutex);

		if (gettimeofday(&sent_timestamp, NULL) == -1)
		{
			LOG("ft_nmap: gettimeofday failed: %s\n", strerror(errno));
			/* Skip this probe rather than computing timestamps from garbage. */
			atomic_fetch_sub(&shared_data->outstanding, 1);
			free(request);
			continue;
		}

		// Compute relative timestamp once for the whole probe (decoys + real)
		compute_relative_timestamp(&relative_sent_timestamp, &sent_timestamp, 
			&shared_data->program_info->start);


		struct in_addr source_ips_list[MAX_DECOYS + 1];
		u8			   send_count = 0;
			bool has_me = false;
		if (shared_data->args && HAS(shared_data->args->flags, F_DECOY))
		{
			for (u8 i = 0; i < shared_data->args->decoy_count; i++)
			{
				source_ips_list[send_count++] = shared_data->args->decoys[i];
				if (shared_data->args->decoys[i].s_addr == INADDR_ANY)
					has_me = true;
			}
		}
		if (!has_me)
		{
			// Place holder in decoy list for our own IP
			source_ips_list[send_count++] = (struct in_addr){ .s_addr = INADDR_ANY };
		}

		t_target		 *target = request->target;
		const u16		  req_port = request->port;
		const t_scan_type req_type = request->type;

		u8	 iface_idx = target->iface_info->iface_index;
		bool tracked
			= false; // true once the real probe lives in the sent queue

		t_udp_probe_payload payloads[MAX_UDP_PAYLOADS_PER_PORT];
		size_t				payload_count = 1;
		payloads[0].data = NULL;
		payloads[0].len = 0;
		if (req_type == SCAN_UDP)
		{
			// Used to identify which service run on port
			size_t n = get_udp_payloads(req_port, payloads,
										MAX_UDP_PAYLOADS_PER_PORT);
			if (n > 0)
				payload_count = n;
		}

		for (u8 i = 0; i < send_count; i++)
		{
			bool		   is_me = (source_ips_list[i].s_addr == INADDR_ANY);
			struct in_addr src
				= is_me ? target->iface_info->ip_addr : source_ips_list[i];

			used_socket = (req_type == SCAN_UDP) ? udp_socket : tcp_socket;
			used_socket.sin.sin_addr = target->addr;
			used_socket.sin.sin_port = htons(req_port);

			if (is_me)
			{
				struct timeval probe_ts = sent_timestamp;
				if (req_type == SCAN_UDP && payload_count > 1)
				{
					double off
						= (double)(payload_count - 1) / MAX_SENT_RATE_UDP_PER_SEC;
					probe_ts.tv_sec += (time_t)off;
					probe_ts.tv_usec += (long)((off - (time_t)off) * 1e6);
					if (probe_ts.tv_usec >= 1000000)
					{
						probe_ts.tv_sec += 1;
						probe_ts.tv_usec -= 1000000;
					}
				}

				pthread_mutex_lock(&shared_data->sent[iface_idx].safe_mut.mutex);
				if (add_to_probe_queue(&shared_data->sent[iface_idx].head,
									   &shared_data->sent[iface_idx].tail,
									   request, probe_ts))
				{
					pthread_mutex_unlock(
						&shared_data->sent[iface_idx].safe_mut.mutex);
					break; // skip remaining decoys for this probe too
				}
				shared_data->sent[iface_idx].nb_probe++;
				tracked = true;
				pthread_mutex_unlock(
					&shared_data->sent[iface_idx].safe_mut.mutex);
			}

			for (size_t p = 0; p < payload_count; p++)
			{
				if (req_type == SCAN_UDP)
					udp_rate_limit(target);

				/* The first probe is sent unconditionaly
				 * So for the next ones we check if we can find the first one
				 * in sent list, if thats not the case then it means the target answered
				 * us already so we do not need to send more payload for this source ip */
				if (send_count == 1 && p > 0 && req_type == SCAN_UDP)
				{
					pthread_mutex_lock(
						&shared_data->sent[iface_idx].safe_mut.mutex);
					bool pending
						= probe_in_queue(shared_data->sent[iface_idx].head,
										 req_port, req_type, target->addr);
					pthread_mutex_unlock(
						&shared_data->sent[iface_idx].safe_mut.mutex);
					if (!pending)
						break;
				}

				memset(packet, 0, sizeof(packet));
				u32 packet_len = 0;
				if (build_scan_packets(target->addr, req_port, req_type, packet,
									   src, &shared_data->id, &packet_len,
									   payloads[p].data, payloads[p].len))
					continue; // header build failed: skip this packet

				t_datalink_hdr datalink_hdr = { 0 };
				const u8	  *l4_hdr = packet + ((t_ip *)packet)->ip_hl * 4;
				if (req_type == SCAN_UDP)
					datalink_hdr.udp_hdr = *(t_udp_hdr *)l4_hdr;
				else
					datalink_hdr.tcp_hdr = *(t_tcp_hdr *)l4_hdr;

				if (shared_data->args
					&& HAS(shared_data->args->flags, F_PACKET_TRACE))
				{
					if (print_debug_packet_send(target->addr, req_type,
												&relative_sent_timestamp,
												&datalink_hdr, (t_ip *)packet,
												!is_me))
					{
						close_sockets(&udp_socket, &tcp_socket);
						return NULL;
					}
				}

				if (send_packet(&used_socket, packet, &sent_timestamp,
								packet_len)
					&& is_me)
					LOG("ft_nmap: failed to send packet to %s\n",
						inet_ntoa(target->addr));
			}
		}

		if (!tracked)
		{
			atomic_fetch_sub(&shared_data->outstanding, 1);
			free(request);
		}
	}
	close_sockets(&udp_socket, &tcp_socket);
	return NULL;
}
