#include "parsing.h"
#include "traceroute.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#define HOP_ADDR_BUF 512
#define HOP_NAME_BUF 256
#define HOP_RTT_BUF 16

/* Index of the answered probe with the lowest RTT, or -1 when the whole hop
 * went unanswered. */
static int best_reply(const t_hop *hop)
{
	int best = -1;

	for (u8 i = 0; i < TRACE_MAX_NQUERIES; i++)
	{
		if (!hop->replies[i].received)
			continue;
		if (best < 0 || hop->replies[i].rtt_ms < hop->replies[best].rtt_ms)
			best = (int)i;
	}
	return best;
}

/* Name of one address: "hostname (ip)" for the destination when target
 * resolution already found a name, plain IP otherwise.
 *
 * Intermediate hops are not resolved: getnameinfo() blocks for seconds on a
 * router without a PTR record. */
static void addr_to_str(struct in_addr addr, const t_target *target, char *out,
						size_t size)
{
	char ip[INET_ADDRSTRLEN];

	if (inet_ntop(AF_INET, &addr, ip, sizeof(ip)) == NULL)
	{
		snprintf(out, size, "?");
		return;
	}

	if (addr.s_addr == target->addr.s_addr && target->hostname != NULL
		&& strcmp(target->hostname, target->input) != 0)
	{
		snprintf(out, size, "%s (%s)", target->hostname, ip);
		return;
	}
	snprintf(out, size, "%s", ip);
}

/* A single hop can be answered by several routers when the path is load
 * balanced, so every distinct address is listed. */
static void hop_to_str(const t_hop *hop, const t_target *target, int best,
					   char *out, size_t size)
{
	struct in_addr seen[TRACE_MAX_NQUERIES];
	u8			   seen_count = 0;
	size_t		   off = 0;

	seen[seen_count++] = hop->replies[best].addr;
	for (u8 i = 0; i < TRACE_MAX_NQUERIES; i++)
	{
		if (!hop->replies[i].received)
			continue;

		bool known = false;
		for (u8 j = 0; j < seen_count; j++)
			known |= (seen[j].s_addr == hop->replies[i].addr.s_addr);
		if (!known)
			seen[seen_count++] = hop->replies[i].addr;
	}

	out[0] = '\0';
	for (u8 i = 0; i < seen_count && off < size; i++)
	{
		char addr_buf[HOP_NAME_BUF];

		addr_to_str(seen[i], target, addr_buf, sizeof(addr_buf));
		const int n = snprintf(out + off, size - off, "%s%s",
							   (i == 0) ? "" : ", ", addr_buf);
		if (n < 0 || (size_t)n >= size - off)
			return;
		off += (size_t)n;
	}
}

/* Consecutive unanswered hops are collapsed on one line, as nmap does:
 * "4   ... 7" means hops 4 through 7 were silent. */
static u8 print_silent_run(const t_hop *hops, u8 hop_count, u8 first)
{
	u8 last = first;

	while (last + 1 < hop_count && best_reply(&hops[last + 1]) < 0)
		last++;

	if (last == first)
		printf("%-3u %s\n", first + 1, "...");
	else
		printf("%-3u %s %u\n", first + 1, "...", last + 1);

	return last;
}

void print_traceroute(const t_target *target, const t_trace_opts *opts)
{
	t_hop hops[TRACE_MAX_HOPS];
	u8	  hop_count = 0;

	if (trace_route(target, opts, hops, &hop_count) == FAILURE)
	{
		printf("\nTRACEROUTE: could not trace the route to %s\n",
			   target->input);
		return;
	}

	/* Each probe uses its own port, so report the range, not just the base. */
	const int probes = (hop_count > 0 ? hop_count : 1) * opts->nqueries;

	switch (trace_mode_from_flags(opts->flags))
	{
	case TRACE_MODE_ICMP:
		printf("\nTRACEROUTE (using proto 1/icmp)\n");
		break;
	case TRACE_MODE_BOTH:
		printf("\nTRACEROUTE (using UDP ports %d-%d and proto 1/icmp)\n",
			   TRACE_BASE_PORT, TRACE_BASE_PORT + probes - 1);
		break;
	default:
		printf("\nTRACEROUTE (using UDP ports %d-%d)\n", TRACE_BASE_PORT,
			   TRACE_BASE_PORT + probes - 1);
		break;
	}
	printf("HOP RTT       ADDRESS\n");

	for (u8 i = 0; i < hop_count; i++)
	{
		const int best = best_reply(&hops[i]);

		if (best < 0)
		{
			i = print_silent_run(hops, hop_count, i);
			continue;
		}

		char rtt[HOP_RTT_BUF];
		char address[HOP_ADDR_BUF];

		snprintf(rtt, sizeof(rtt), "%.2f ms", hops[i].replies[best].rtt_ms);
		hop_to_str(&hops[i], target, best, address, sizeof(address));
		printf("%-3u %-9s %s\n", i + 1, rtt, address);
	}
}
