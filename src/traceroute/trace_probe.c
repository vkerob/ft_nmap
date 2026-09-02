#include "my_signal.h"
#include "traceroute.h"

#include <errno.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#define ICMP_OFF_TYPE 0
#define ICMP_OFF_CODE 1
#define ICMP_OFF_CKSUM 2
#define ICMP_OFF_ID 4
#define ICMP_OFF_SEQ 6

static u16 icmp_read_u16(const u8 *icmp, size_t offset)
{
	u16 value;

	memcpy(&value, icmp + offset, sizeof(value));
	return ntohs(value);
}

static void icmp_write_u16(u8 *icmp, size_t offset, u16 value)
{
	const u16 net_value = htons(value);

	memcpy(icmp + offset, &net_value, sizeof(net_value));
}

static u16 probe_seq(const t_trace_opts *opts, int ttl, int probe)
{
	return (u16)((ttl - 1) * opts->nqueries + probe);
}

static size_t inner_l4_offset(const u8 *buf, ssize_t n, size_t ip_hlen,
							  size_t l4_hdr_len)
{
	t_ip		 inner_ip;
	const size_t inner_off = ip_hlen + ICMP_HDR_LEN;

	if ((size_t)n < inner_off + sizeof(t_ip))
		return 0;

	memcpy(&inner_ip, buf + inner_off, sizeof(inner_ip));
	const size_t inner_ip_hlen = (size_t)inner_ip.ip_hl * 4;
	if (inner_ip_hlen < sizeof(t_ip))
		return 0;
	if ((size_t)n < inner_off + inner_ip_hlen + l4_hdr_len)
		return 0;

	return inner_off + inner_ip_hlen;
}

static bool match_inner_udp(const u8 *buf, ssize_t n, size_t ip_hlen,
							const t_trace_opts *opts, int ttl, int probe)
{
	t_udp_hdr	 inner_udp;
	const size_t off = inner_l4_offset(buf, n, ip_hlen, sizeof(t_udp_hdr));

	if (off == 0)
		return false;

	memcpy(&inner_udp, buf + off, sizeof(inner_udp));
	const u16 expected_port = TRACE_BASE_PORT + probe_seq(opts, ttl, probe);

	return ntohs(inner_udp.uh_dport) == expected_port;
}

static bool match_inner_echo(const u8 *buf, ssize_t n, size_t ip_hlen,
							 const t_trace_ctx *ctx, const t_trace_opts *opts,
							 int ttl, int probe)
{
	const size_t off = inner_l4_offset(buf, n, ip_hlen, ICMP_HDR_LEN);

	if (off == 0)
		return false;

	const u8 *inner_icmp = buf + off;

	if (icmp_read_u16(inner_icmp, ICMP_OFF_ID) != ctx->echo_id)
		return false;
	return icmp_read_u16(inner_icmp, ICMP_OFF_SEQ)
		   == probe_seq(opts, ttl, probe);
}

static bool handle_udp_reply(const u8 *buf, ssize_t n, size_t ip_hlen,
							 const u8 *icmp, const t_trace_opts *opts, int ttl,
							 int probe, t_trace_reply *reply)
{
	switch (icmp[ICMP_OFF_TYPE])
	{
	case TRACE_ICMP_TIME_EXCEEDED:
		if (!match_inner_udp(buf, n, ip_hlen, opts, ttl, probe))
			return false;
		reply->reached_dst = false;
		return true;

	case TRACE_ICMP_DEST_UNREACH:
		if (!match_inner_udp(buf, n, ip_hlen, opts, ttl, probe))
			return false;
		if (icmp[ICMP_OFF_CODE] == TRACE_ICMP_PORT_UNREACH)
		{
			reply->reached_dst = true;
			return true;
		}
		return false;

	default:
		return false;
	}
}

static bool handle_icmp_reply(const u8 *buf, ssize_t n, size_t ip_hlen,
							  const u8 *icmp, const t_trace_ctx *ctx,
							  const t_trace_opts *opts, int ttl, int probe,
							  t_trace_reply *reply)
{
	switch (icmp[ICMP_OFF_TYPE])
	{
	case TRACE_ICMP_TIME_EXCEEDED:
		if (!match_inner_echo(buf, n, ip_hlen, ctx, opts, ttl, probe))
			return false;
		reply->reached_dst = false;
		return true;

	case ICMP_ECHOREPLY:
		if (icmp_read_u16(icmp, ICMP_OFF_ID) != ctx->echo_id)
			return false;
		if (icmp_read_u16(icmp, ICMP_OFF_SEQ) != probe_seq(opts, ttl, probe))
			return false;
		reply->reached_dst = true;
		return true;

	default:
		return false;
	}
}

static double time_diff_ms(const struct timeval *start,
						   const struct timeval *end)
{
	const double sec = (double)(end->tv_sec - start->tv_sec);
	const double usec = (double)(end->tv_usec - start->tv_usec);

	return sec * 1000.0 + usec / 1000.0;
}

int trace_receive_reply(t_trace_ctx *ctx, const t_trace_opts *opts, int ttl,
						int probe, t_trace_reply *reply, struct timeval *start)
{
	fd_set		   rfds;
	struct timeval end;
	u8			   buf[512];

	while (g_interrupted != 1)
	{
		FD_ZERO(&rfds);
		FD_SET(ctx->sock_icmp, &rfds);

		struct timeval tv = { .tv_sec = 0, .tv_usec = TRACE_PROBE_TIMEOUT_US };
		const int	   ret = select(ctx->sock_icmp + 1, &rfds, NULL, NULL, &tv);
		if (ret < 0)
		{
			if (errno == EINTR)
				continue;
			LOG("ft_nmap: traceroute: select failed: %s\n", strerror(errno));
			return FAILURE;
		}
		if (ret == 0)
			return TRACE_NO_REPLY;
		if (!FD_ISSET(ctx->sock_icmp, &rfds))
			continue;

		struct sockaddr_in from;
		socklen_t		   fromlen = sizeof(from);

		const ssize_t n = recvfrom(ctx->sock_icmp, buf, sizeof(buf), 0,
								   (struct sockaddr *)&from, &fromlen);
		if (n < 0)
		{
			if (errno == EINTR)
				continue;
			LOG("ft_nmap: traceroute: recvfrom failed: %s\n", strerror(errno));
			return FAILURE;
		}

		if (gettimeofday(&end, NULL) == -1)
		{
			LOG("ft_nmap: traceroute: gettimeofday failed: %s\n",
				strerror(errno));
			return FAILURE;
		}

		if ((size_t)n < sizeof(t_ip))
			continue;

		t_ip ip_hdr;
		memcpy(&ip_hdr, buf, sizeof(ip_hdr));
		const size_t ip_hlen = (size_t)ip_hdr.ip_hl * 4;
		if (ip_hlen < sizeof(t_ip) || (size_t)n < ip_hlen + ICMP_HDR_LEN)
			continue;

		const u8 *icmp = buf + ip_hlen;

		memset(reply, 0, sizeof(*reply));
		reply->addr = from;
		reply->rtt_ms = time_diff_ms(start, &end);
		reply->icmp_type = icmp[ICMP_OFF_TYPE];
		reply->icmp_code = icmp[ICMP_OFF_CODE];
		reply->reached_dst = false;

		/* In BOTH mode either probe may be the one that got through. The two
		 * matchers key on different fields — the echoed UDP port, our ICMP id
		 * and sequence — so a reply cannot satisfy the wrong one. */
		bool handled = false;

		if (ctx->mode != TRACE_MODE_UDP)
			handled = handle_icmp_reply(buf, n, ip_hlen, icmp, ctx, opts, ttl,
										probe, reply);
		if (!handled && ctx->mode != TRACE_MODE_ICMP)
			handled = handle_udp_reply(buf, n, ip_hlen, icmp, opts, ttl, probe,
									   reply);
		if (handled)
			return SUCCESS;
	}
	return TRACE_NO_REPLY;
}

static u16 icmp_checksum(const void *packet, int packet_len)
{
	const u8 *bytes = packet;
	u32		  sum = 0;

	while (packet_len > 1)
	{
		u16 word;
		memcpy(&word, bytes, sizeof(word));
		sum += word;
		bytes += 2;
		packet_len -= 2;
	}
	if (packet_len == 1) // odd trailing byte
		sum += *bytes;

	sum = (sum & 0xFFFF) + (sum >> 16); // fold the 32-bit sum to 16 bits
	sum += (sum >> 16);					// in case the fold itself carried
	return (u16)~sum;
}

static void fill_payload(u8 *payload, size_t len, int ttl, int probe)
{
	static const char pattern[]
		= "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz";
	const size_t pattern_len = sizeof(pattern) - 1;

	if (len == 0)
		return;

	int hdr_len
		= snprintf((char *)payload, len, "ft_nmap ttl=%d probe=%d", ttl, probe);
	if (hdr_len < 0)
		hdr_len = 0;
	if ((size_t)hdr_len > len)
		hdr_len = (int)len;

	for (size_t i = (size_t)hdr_len; i < len; i++)
		payload[i] = (u8)pattern[(i - (size_t)hdr_len) % pattern_len];
}

static int send_udp_probe(t_trace_ctx *ctx, const t_trace_opts *opts, int ttl,
						  int probe)
{
	struct sockaddr_in dst = ctx->dst;
	const size_t	   len = (size_t)(opts->packetlen - TRACE_PACKET_LEN_MIN);
	u8				   payload[len ? len : 1];

	dst.sin_port = htons((u16)(TRACE_BASE_PORT + probe_seq(opts, ttl, probe)));
	fill_payload(payload, len, ttl, probe);

	if (sendto(ctx->sock_udp, payload, len, 0, (struct sockaddr *)&dst,
			   sizeof(dst))
		< 0)
	{
		LOG("ft_nmap: traceroute: sendto failed: %s\n", strerror(errno));
		return FAILURE;
	}
	return SUCCESS;
}

static int send_icmp_probe(t_trace_ctx *ctx, const t_trace_opts *opts, int ttl,
						   int probe)
{
	const struct sockaddr_in dst = ctx->dst;
	const size_t packet_len = (size_t)(opts->packetlen - TRACE_IP_HEADER_LEN);
	u8			 packet[packet_len];

	memset(packet, 0, packet_len);

	if (ctx->echo_id == 0)
		ctx->echo_id = (u16)(getpid() & 0xFFFF);

	packet[ICMP_OFF_TYPE] = ICMP_ECHO;
	packet[ICMP_OFF_CODE] = 0;
	icmp_write_u16(packet, ICMP_OFF_ID, ctx->echo_id);
	icmp_write_u16(packet, ICMP_OFF_SEQ, probe_seq(opts, ttl, probe));

	fill_payload(packet + ICMP_HDR_LEN, packet_len - ICMP_HDR_LEN,
				 ttl, probe);

	/* Checksum covers header + payload, and is computed with the field
	 * zeroed (memset above). No pseudo-header, unlike TCP and UDP. */
	const u16 cksum = icmp_checksum(packet, (int)packet_len);
	memcpy(packet + ICMP_OFF_CKSUM, &cksum, sizeof(cksum));

	if (sendto(ctx->sock_icmp, packet, packet_len, 0,
			   (const struct sockaddr *)&dst, sizeof(dst))
		< 0)
	{
		LOG("ft_nmap: traceroute: sendto ICMP failed: %s\n", strerror(errno));
		return FAILURE;
	}
	return SUCCESS;
}

/* Sends every probe kind the mode calls for, under a single timestamp.
 * Succeeds as long as one probe reached the wire. */
int trace_send_probe(t_trace_ctx *ctx, const t_trace_opts *opts, int ttl,
					 int probe, struct timeval *start)
{
	int sent = 0;

	if (gettimeofday(start, NULL) == -1)
	{
		LOG("ft_nmap: traceroute: gettimeofday failed: %s\n", strerror(errno));
		return FAILURE;
	}

	if (ctx->mode != TRACE_MODE_ICMP
		&& send_udp_probe(ctx, opts, ttl, probe) == SUCCESS)
		sent++;
	if (ctx->mode != TRACE_MODE_UDP
		&& send_icmp_probe(ctx, opts, ttl, probe) == SUCCESS)
		sent++;

	return (sent > 0) ? SUCCESS : FAILURE;
}
