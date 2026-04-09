#include "scan.h"

#define PRINT_LIMIT 25

// ── Helpers
// ───────────────────────────────────────────────────────────────────

static const char *port_state_to_str(t_port_state state)
{
	switch (state)
	{
	case OPEN:
		return "open";
	case CLOSE:
		return "closed";
	case FILTERED:
		return "filtered";
	case UNFILTERED:
		return "unfiltered";
	case OPEN_FILTERED:
		return "open|filtered";
	default:
		return "unknown";
	}
}

static const char *port_state_color(t_port_state state)
{
	switch (state)
	{
	case OPEN:
		return ANSI_COLOR_GREEN;
	case FILTERED:
		return ANSI_COLOR_YELLOW;
	case OPEN_FILTERED:
		return ANSI_COLOR_YELLOW;
	case UNFILTERED:
		return ANSI_COLOR_CYAN;
	case CLOSE:
		return ANSI_COLOR_RED;
	default:
		return ANSI_COLOR_RESET;
	}
}

static const char *get_service_name(u16 port)
{
	const struct servent *svc = getservbyport(htons(port), "tcp");
	if (svc)
		return svc->s_name;
	svc = getservbyport(htons(port), "udp");
	if (svc)
		return svc->s_name;
	return "unknown";
}
// Determine overall conclusion for a port across all scan types.
//
// We check for OPEN and CLOSE status first because it gives a definitive
// answer:
//   - SYN → OPEN  (SYN-ACK): return immediately, no ambiguity.
//   - SYN, XMAS, URG, NULL and UDP → CLOSE (RST): return immediately, no
//   ambiguity.
//
static t_port_state get_port_conclusion(const t_target *target, const t_args *args,
										const u16 port)
{
	// Check if we have a definite answer for the port's state (OPEN or CLOSE)
	// for each scan type we launched and in which case we return immediately

	bool open_filtered = false;
	bool filtered = false;
	bool unfiltered = false;

	for (u8 i = 0; i < args->nb_scan_types; i++) {
		const t_scan_type stype = args->scan_types[i];
		const u16 idx = target->port_list.port_map[port];

		const t_port_state state
			= target->port_list.port_map_rev[stype][idx].port_state;

		switch (state) {
			case OPEN:
			case CLOSE:
				return state;
			case OPEN_FILTERED:
				open_filtered = true;
				break;
			case FILTERED:
				// We don't return here since another type of scan can give us open or close.
				filtered = true;
				break;
			case UNFILTERED:
				// We don't return here since another type of scan can give us open or close.
				unfiltered = true;
				break;
			case UNKNOWN:
				break;
		}
	}
	if (open_filtered)
		return OPEN_FILTERED;
	if (filtered)
		return FILTERED;
	if (unfiltered)
		return UNFILTERED;

	return UNKNOWN;
}

// Builds the "Not shown:" summary line for all states which have a number
// ports over PRINT_LIMIT
//static void build_not_shown_str(u16 nb_closed, u16 nb_filtered,
//								u16 nb_open_filtered)
//{
//	struct s_entry
//	{
//		u16			count;
//		const char *label;
//		const char *reason;
//	} entries[3];
//	u8 nb_entries = 0;
//
//	if (nb_closed > 0)
//	{
//		entries[nb_entries].count = nb_closed;
//		entries[nb_entries].label = "closed tcp";
//		entries[nb_entries].reason = "reset";
//		nb_entries++;
//	}
//	if (nb_filtered > 0)
//	{
//		entries[nb_entries].count = nb_filtered;
//		entries[nb_entries].label = "filtered tcp";
//		entries[nb_entries].reason = "no-response";
//		nb_entries++;
//	}
//	if (nb_open_filtered > 0)
//	{
//		entries[nb_entries].count = nb_open_filtered;
//		entries[nb_entries].label = "open|filtered tcp";
//		entries[nb_entries].reason = "no-response";
//		nb_entries++;
//	}
//
//	if (nb_entries == 0)
//		return;
//
//	printf("Not shown: ");
//	for (u8 i = 0; i < nb_entries; i++)
//	{
//		if (i > 0)
//			printf(", ");
//		printf("%u %s port%s (%s)", entries[i].count, entries[i].label,
//			   entries[i].count > 1 ? "s" : "", entries[i].reason);
//	}
//	printf("\n");
//}

static void build_results_str(const t_target *target, const t_args *args, const u16 port,
							  char *buf, size_t buf_size)
{
	char   scan_name[16];
	size_t offset = 0;

	for (u8 i = 0; i < args->nb_scan_types; i++)
	{
		const t_scan_type	 stype = args->scan_types[i];
		const u16			 idx = target->port_list.port_map[port];
		const t_port_state state
			= target->port_list.port_map_rev[stype][idx].port_state;

		scan_type_to_str(stype, scan_name);

		const int written = snprintf(buf + offset, buf_size - offset, "%s(%s) ",
							   scan_name, port_state_to_str(state));
		if (written < 0 || (size_t)written >= buf_size - offset)
			break;
		offset += (size_t)written;
	}
	if (offset > 0 && buf[offset - 1] == ' ')
		buf[offset - 1] = '\0';
}

// Compute max "port/proto" string width across all ports of a target
// so that columns align regardless of port numbers (like nmap does).
static int compute_port_col_width(t_args *args)
{
	int max = 9; // minimum: "65535/tcp"
	for (u16 i = 0; i < args->port_count; i++)
	{
		const int w = snprintf(NULL, 0, "%u/tcp", args->ports[i]);
		if (w > max)
			max = w;
	}
	return max + 2; // extra padding like nmap
}



static void print_target_results(t_target *target, t_args *args)
{
	char ip_str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &target->addr, ip_str, sizeof(ip_str));

	printf("Nmap scan report for %s\n", ip_str);
	printf("Host is up.\n");

	for (u16 i = 0; i < args->port_count; i++)
	{
		const t_port_state port_state = get_port_conclusion(target, args, args->ports[i]);
		target->port_list.state_count[port_state]++;
		const u16 idx = target->port_list.port_map[args->ports[i]];
		target->port_list.port_final_state[idx] = port_state;
	}


	// If we got no port's open and all port state occurrences exceed 25
	//if (nb_open == 0)
	//{
	//	printf("All %u scanned ports on %s are in ignored states.\n",
	//			   args->port_count, ip_str);
	//	build_not_shown_str(nb_closed, nb_filtered, nb_open_filtered);
	//}

	bool has_udp = false;
	bool has_tcp = false;
	for (u8 i = 0; i < args->nb_scan_types; i++)
	{
		if (args->scan_types[i] == SCAN_UDP)
			has_udp = true;
		else
			has_tcp = true;
	}
	(void)has_tcp;


	const int  col_port = compute_port_col_width(args);
	const int  col_state = 14;
	const int  col_svc = 12;
	const bool multi_scan = args->nb_scan_types > 1;

	if (multi_scan)
		printf("%-*s %-*s %-*s %s\n", col_port, "PORT", col_state, "STATE",
			   col_svc, "SERVICE", "SCAN RESULTS");
	else
		printf("%-*s %-*s %s\n", col_port, "PORT", col_state, "STATE",
			   "SERVICE");

	for (u16 i = 0; i < args->port_count; i++)
	{
		const u16 port = args->ports[i];
		const u16 idx = target->port_list.port_map[args->ports[i]];
		const t_port_state conclusion = target->port_list.port_final_state[idx];

		if (conclusion != OPEN && target->port_list.state_count[conclusion] > PRINT_LIMIT) {
			continue ;
		}

		char port_str[16];
		if (has_udp && !has_tcp)
			snprintf(port_str, sizeof(port_str), "%u/udp", port);
		else
			snprintf(port_str, sizeof(port_str), "%u/tcp", port);

		const char *svc = get_service_name(port);
		const char *color = port_state_color(conclusion);
		const char *state = port_state_to_str(conclusion);

		if (multi_scan)
		{
			char results_buf[256];
			build_results_str(target, args, port, results_buf,
							  sizeof(results_buf));
			printf("%-*s %s%-*s%s %-*s %s\n", col_port, port_str, color,
				   col_state, state, ANSI_COLOR_RESET, col_svc, svc,
				   results_buf);
		}
		else
		{
			printf("%-*s %s%-*s%s %s\n", col_port, port_str, color, col_state,
				   state, ANSI_COLOR_RESET, svc);
		}
	}
}

void print_scan_results(t_ctx *ctx)
{
	struct timeval now;
	gettimeofday(&now, NULL);

	const double elapsed
		= (double)(now.tv_sec - ctx->program_info.start.tv_sec)
		  + (double)(now.tv_usec - ctx->program_info.start.tv_usec) / 1e6;

	for (size_t i = 0; i < ctx->target_count; i++)
		print_target_results(&ctx->targets[i], &ctx->args);

	printf("\nft_nmap done: %zu IP address%s (%zu host%s up) scanned in %.2f "
		   "seconds\n",
		   ctx->target_count, ctx->target_count > 1 ? "es" : "",
		   ctx->target_count, ctx->target_count > 1 ? "s" : "", elapsed);
}
