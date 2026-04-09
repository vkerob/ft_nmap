#include "scan.h"

#include <string.h>

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

// Return the next most common ignored state (which the most port shared a state)
// or unknown if none are left
static t_port_state get_next_ignored_state(const int *state_count)
{
	static t_port_state prev_ignored_state = UNKNOWN;

	int max = PRINT_LIMIT; 
	t_port_state next_ignored_state = UNKNOWN;
	for (u8 i = 0; i < HIGHEST_PORT_STATE; i++)
	{
		if (i == prev_ignored_state)
		{
			continue ;
		}
		int count = state_count[i];
		if (count > max)
		{
			max = count;
			next_ignored_state = i;
		}
	}

	if (prev_ignored_state == next_ignored_state)
	{
		return UNKNOWN;
	}
	prev_ignored_state = next_ignored_state;
	return next_ignored_state;
}

/* This is for a special case when some port can be filtered because we got a IMCP error unreachable code, and other can be filtered 
because we didn't get any response. In this  case we separate the 'not shown' output between those two reasons */
static void get_common_reason(t_port *port_final_state, u16 port_count, char *next_common_reason, int *common_reason_count)
{
	int count_reason1 = 0;
	int count_reason2 = 0;
	char reason1[16] = {0};
	char reason2[16] = {0};

	for (u16 i = 0; i < port_count; i++)
	{
		if (reason1[0] == '\0'){
			strcpy(reason1, port_final_state[i].reason);
			count_reason1++;
		}
		else if (reason2[0] == '\0'){
			strcpy(reason2, port_final_state[i].reason);
			count_reason2++;
		}
		else{
			if (strcmp(reason1, port_final_state[i].reason)){
				count_reason1++;
			}
			else if (strcmp(reason2, port_final_state[i].reason)){
				count_reason2++;
			}
		}
	}

	if (count_reason1 > count_reason2){
		strcpy(next_common_reason, reason1);
		*common_reason_count = count_reason1;
	}
	else{
		strcpy(next_common_reason, reason2);
		*common_reason_count = count_reason2;
	}
}

char *state_to_label(t_port_state state)
{
	switch (state){
		case OPEN_FILTERED:
			return "open|filtered";
		case UNFILTERED:
			return "unfiltered";
		case FILTERED:
			return "filtered";
		case CLOSE:
			return "close";
		case OPEN:
			return "open";
		case UNKNOWN:
			return "unknown";
	}
	return NULL;
}

// Builds the "Not shown:" summary line for all states except OPEN which have a number
// ports over PRINT_LIMIT in which case they are considered "ignored".
// They are print from the most common to the least common and with a reason associated (no-response, reset, ...)
static void build_not_shown_str(int *state_count, t_port **port_final_state, u16 port_count,
	bool tcp_scan, bool udp_scan)
{
	t_port_state next_ignore_state = get_next_ignored_state(state_count);
	// struct s_entry
	// {
	// 	u16			count;
	// 	const char *label;
	// 	const char *reason;
	// } entries[3];
	// u8 nb_entries = 0;

	if (next_ignore_state != UNKNOWN){
		printf("Not shown: ");
	}
	char reasons[2][16] = {0};
	while (next_ignore_state != UNKNOWN){
		char *state_label = state_to_label(next_ignore_state);
		int count = state_count[next_ignore_state];
		/* sub count for first reason (is equal to total count if only one reason)*/
		int sub_count_1 = 0;
		if (tcp_scan)
		{
			get_common_reason(port_final_state[0], port_count, reasons[0], &sub_count_1);
			/* If we have more than two reason
			Ex: Half the port were filtered because 'no-response' and the other half because we got icmp error code */
			if (sub_count_1 == count){
				printf("%u tcp port%s (%s)", count, state_label, count > 1 ? "s" : "", reasons[0]);
			}
			else {
				get_common_reason(port_final_state[0], port_count, reasons[1], &sub_count_2);
				printf("%u tcp port%s (%s), %u tcp port%s (%s)", sub_count_1, state_label, sub_count_1 > 1 ? "s" : "", reasons[0],
				sub_count_2, state_label, sub_count_2 > 1 ? "s" : "", reasons[1]);
			}
		}
		// If we got both tcp scan and udp we need to separate the output like so:
		// Not shown: 16 open|filtered udp ports (no-response), 16 open|filtered tcp ports (no-response)
		if (udp_scan)
		{
			memset(reasons, 0, sizeof(reasons));
			if (tcp_scan)
			{
				printf(", ");
			}
			get_common_reason(port_final_state[1], port_count, reasons[0], &sub_count_1);
			/* If we have more than two reason
				Ex: Not shown: 16 open|filtered udp ports (no-response), 16 open|filtered udp ports (icmp-unreachable-error) */
			if (sub_count_1 == count){
				printf("%u udp port%s (%s)\n", count, state_label, count > 1 ? "s" : "", reasons[0]);
			}
			else {
				get_common_reason(port_final_state[1], port_count, reasons[1], &sub_count_2);
				printf("%u udp port%s (%s), %u udp port%s (%s)", sub_count_1, state_label, sub_count_1 > 1 ? "s" : "", reasons[0],
				sub_count_2, state_label, sub_count_2 > 1 ? "s" : "", reasons[1]);
			}
		}
		printf("\n");
		next_ignore_state = get_next_ignored_state(state_count);
	}

//
//	if (nb_closed > 0)
//	{
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
}

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

	bool udp_scan = false;
	bool tcp_scan = false;
	for (u8 i = 0; i < args->nb_scan_types; i++)
	{
		udp_scan |= (args->scan_types[i] == SCAN_UDP);
		tcp_scan |= (args->scan_types[i] != SCAN_UDP);
	}

	for (u16 i = 0; i < args->port_count; i++)
	{
		const t_port_state port_state = get_port_conclusion(target, args, args->ports[i]);
		if (tcp_scan)
		{
			target->port_list.state_count[port_state]++;
		}
		if (udp_scan)
		{
			target->port_list.state_count[port_state]++;
		}
		const u16 idx = target->port_list.port_map[args->ports[i]];
		target->port_list.port_final_state[idx]->port_state = port_state;
		//TODO: we need to be able 4 reasons for each port (2 TCP 2 UDP)
		target->port_list.port_final_state[idx]->reason = args->
	}

	build_not_shown_str(target->port_list.state_count, target->port_list.port_final_state,
		args->port_count, tcp_scan, udp_scan);

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
