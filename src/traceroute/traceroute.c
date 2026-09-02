#include "traceroute.h"
#include "my_signal.h"

#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

t_trace_mode trace_mode_from_flags(u8 flags)
{
	const bool udp = HAS(flags, F_TR_UDP);
	const bool icmp = HAS(flags, F_TR_ICMP);

	if (udp && icmp)
		return TRACE_MODE_BOTH;
	if (icmp)
		return TRACE_MODE_ICMP;
	return TRACE_MODE_UDP;
}

void trace_opts_init(t_trace_opts *opts)
{
	memset(opts, 0, sizeof(*opts));
	opts->packetlen = TRACE_DEFAULT_PACKETLEN;
	opts->max_hops = TRACE_DEFAULT_MAX_HOPS;
	opts->nqueries = TRACE_DEFAULT_NQUERIES;
	SET(opts->flags, F_TR_UDP);
}

static int trace_opts_valid(const t_trace_opts *opts)
{
	if (opts->packetlen < TRACE_PACKET_LEN_MIN
		|| opts->packetlen > TRACE_PACKET_LEN_MAX)
	{
		LOG("ft_nmap: traceroute: packet length must be within %d-%d\n",
			TRACE_PACKET_LEN_MIN, TRACE_PACKET_LEN_MAX);
		return FAILURE;
	}
	if (opts->max_hops < 1 || opts->max_hops > TRACE_MAX_HOPS)
	{
		LOG("ft_nmap: traceroute: max hops must be within 1-%d\n",
			TRACE_MAX_HOPS);
		return FAILURE;
	}
	if (opts->nqueries < 1 || opts->nqueries > TRACE_MAX_NQUERIES)
	{
		LOG("ft_nmap: traceroute: queries per hop must be within 1-%d\n",
			TRACE_MAX_NQUERIES);
		return FAILURE;
	}
	return SUCCESS;
}

/* Hop distance to the target, deduced from the TTL of the reply the scan
 * captured. The sender's initial TTL is not on the wire, but stacks pick one
 * of a few standard values, so rounding the observed TTL up to the next one
 * gives the number of routers it crossed; the target sits one hop past them.
 *
 * Returns opts->max_hops when no reply was captured. */
static int estimate_max_hops(const t_target *target, const t_trace_opts *opts)
{
	static const u8 initial_ttls[] = { 32, 64, 128, 255 };

	const u8 observed = target->reply_ttl;

	if (observed == 0)
		return opts->max_hops;

	for (size_t i = 0; i < sizeof(initial_ttls) / sizeof(initial_ttls[0]); i++)
	{
		if (observed > initial_ttls[i])
			continue;

		const int distance = initial_ttls[i] - observed + 1;
		const int bounded = distance + TRACE_TTL_MARGIN;

		return (bounded < opts->max_hops) ? bounded : opts->max_hops;
	}
	return opts->max_hops;
}

/* Set on every socket that sends a probe. */
static int set_ttl(const t_trace_ctx *ctx, int ttl)
{
	if (ctx->sock_udp >= 0
		&& setsockopt(ctx->sock_udp, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
	{
		LOG("ft_nmap: traceroute: setsockopt(IP_TTL) on UDP failed: %s\n",
			strerror(errno));
		return FAILURE;
	}
	if (ctx->mode != TRACE_MODE_UDP
		&& setsockopt(ctx->sock_icmp, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl))
			   < 0)
	{
		LOG("ft_nmap: traceroute: setsockopt(IP_TTL) on ICMP failed: %s\n",
			strerror(errno));
		return FAILURE;
	}
	return SUCCESS;
}

/* Probe one TTL. Returns FAILURE only when the trace itself cannot go on;
 * a probe that goes unanswered simply leaves its slot untouched. */
static int trace_one_hop(t_trace_ctx *ctx, const t_trace_opts *opts, int ttl,
						 t_hop *hop)
{
	memset(hop, 0, sizeof(*hop));

	if (set_ttl(ctx, ttl) == FAILURE)
		return FAILURE;

	for (int probe = 0; probe < opts->nqueries && g_interrupted != 1; probe++)
	{
		struct timeval start;

		hop->nb_probes++;
		if (trace_send_probe(ctx, opts, ttl, probe, &start) == FAILURE)
			continue;

		t_trace_reply reply;
		const int	  rc
			= trace_receive_reply(ctx, opts, ttl, probe, &reply, &start);
		if (rc == FAILURE)
			return FAILURE;
		if (rc == TRACE_NO_REPLY)
			continue;

		hop->replies[probe].received = true;
		hop->replies[probe].addr = reply.addr.sin_addr;
		hop->replies[probe].rtt_ms = reply.rtt_ms;
		if (reply.reached_dst)
			hop->reached_dst = true;
	}
	return SUCCESS;
}

int trace_route(const t_target *target, const t_trace_opts *opts, t_hop *hops,
				u8 *hop_count)
{
	t_trace_ctx ctx;

	if (target == NULL || opts == NULL || hops == NULL || hop_count == NULL)
		return FAILURE;
	if (trace_opts_valid(opts) == FAILURE)
		return FAILURE;

	*hop_count = 0;

	memset(&ctx, 0, sizeof(ctx));
	ctx.sock_udp = -1;
	ctx.sock_icmp = -1;
	ctx.echo_id = (u16)(getpid() & 0xFFFF);
	ctx.dst.sin_family = AF_INET;
	ctx.dst.sin_addr = target->addr;

	if (trace_init_sockets(&ctx, opts) == FAILURE)
		return FAILURE;

	const int max_hops = estimate_max_hops(target, opts);

	for (int ttl = 1; ttl <= max_hops && g_interrupted != 1; ttl++)
	{
		t_hop *hop = &hops[ttl - 1];

		if (trace_one_hop(&ctx, opts, ttl, hop) == FAILURE)
		{
			trace_close_sockets(&ctx);
			return FAILURE;
		}
		(*hop_count)++;

		if (hop->reached_dst)
			break;
	}

	trace_close_sockets(&ctx);
	return SUCCESS;
}
