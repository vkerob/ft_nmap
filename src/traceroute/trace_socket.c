#include "traceroute.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

void trace_close_sockets(t_trace_ctx *ctx)
{
	if (ctx->sock_udp >= 0)
	{
		close(ctx->sock_udp);
		ctx->sock_udp = -1;
	}
	if (ctx->sock_icmp >= 0)
	{
		close(ctx->sock_icmp);
		ctx->sock_icmp = -1;
	}
}

int trace_init_sockets(t_trace_ctx *ctx, const t_trace_opts *opts)
{
	ctx->mode = trace_mode_from_flags(opts->flags);

	/* Routers answer with ICMP whatever was sent to them, so this is the
	 * receiving socket in every mode, and the sending one in ICMP mode. */
	ctx->sock_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (ctx->sock_icmp < 0)
	{
		LOG("ft_nmap: traceroute: ICMP socket failed: %s\n", strerror(errno));
		return FAILURE;
	}

	if (ctx->mode != TRACE_MODE_ICMP)
	{
		ctx->sock_udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (ctx->sock_udp < 0)
		{
			LOG("ft_nmap: traceroute: UDP send socket failed: %s\n",
				strerror(errno));
			close(ctx->sock_icmp);
			ctx->sock_icmp = -1;
			return FAILURE;
		}
	}
	return SUCCESS;
}
