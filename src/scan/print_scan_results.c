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
	case CLOSE_FILTERED:
		return "closed|filtered";
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

static const char *get_service_name(uint16_t port)
{
	struct servent *svc = getservbyport(htons(port), "tcp");
	if (svc)
		return svc->s_name;
	svc = getservbyport(htons(port), "udp");
	if (svc)
		return svc->s_name;
	return "unknown";
}

// Determine overall conclusion for a port across all scan types.
//
// SYN is checked first because it gives the most definitive answer:
//   - SYN → OPEN  (SYN-ACK): return immediately, no ambiguity.
//   - SYN → CLOSE (RST)    : return immediately, no ambiguity.
//   - SYN → FILTERED       : fall through to aggregation with other scans.
//
// If we reach the aggregation loop, SYN's state is included so that a
// SYN-only scan with no response correctly returns FILTERED instead of
// UNKNOWN (the old code skipped SYN in the loop, losing that information).
//
// Priority across all non-authoritative results:
//   open > open|filtered > unfiltered > filtered > closed
static t_port_state get_port_conclusion(t_target *target, t_args *args,
										u16 port)
{
	// SYN is authoritative for OPEN and CLOSE — return immediately.
	for (u8 i = 0; i < args->nb_scan_types; i++)
	{
		if (args->scan_types[i] != SCAN_SYN)
			continue;
		u16			 idx = target->port_list.port_map[SCAN_SYN][port];
		t_port_state state
			= target->port_list.port_map_rev[SCAN_SYN][idx].port_state;
		if (state == OPEN || state == CLOSE)
			return state;
		break; // SYN gave FILTERED: fall through to aggregation
	}

	// Aggregate ALL scans (SYN included for its non-OPEN/CLOSE result).
	// Because OPEN/CLOSE already returned above, SYN can only contribute
	// FILTERED here — which is exactly what we want for a SYN-only scan.
	bool has_open = false;
	bool has_close = false;
	bool has_filtered = false;
	bool has_unfiltered = false;
	bool has_open_filtered = false;

	for (u8 i = 0; i < args->nb_scan_types; i++)
	{
		t_scan_type	 stype = args->scan_types[i];
		u16			 idx = target->port_list.port_map[stype][port];
		t_port_state state
			= target->port_list.port_map_rev[stype][idx].port_state;

		switch (state)
		{
		case OPEN:
			has_open = true;
			break;
		case CLOSE:
			has_close = true;
			break;
		case FILTERED:
			has_filtered = true;
			break;
		case UNFILTERED:
			has_unfiltered = true;
			break;
		case OPEN_FILTERED:
			has_open_filtered = true;
			break;
		default:
			break;
		}
	}

	if (has_open)
		return OPEN;
	if (has_open_filtered)
		return OPEN_FILTERED;
	if (has_unfiltered)
		return UNFILTERED;
	if (has_filtered)
		return FILTERED;
	if (has_close)
		return CLOSE;
	return UNKNOWN;
}

// Returns true for states that are "boring" and hidden in "Not shown".
// Interesting states (OPEN, UNFILTERED, OPEN_FILTERED, CLOSE_FILTERED) are
// always shown in the table because they carry useful information.
// Only CLOSE (definitive RST) and FILTERED (definitive block) are truly dull.
// UNKNOWN means no data at all — also boring.
static bool is_boring(t_port_state state)
{
	return state == CLOSE || state == FILTERED || state == OPEN_FILTERED
		   || state == CLOSE_FILTERED || state == UNKNOWN;
}

// Builds the "Not shown:" summary line for all boring hidden states.
// nmap hides CLOSE, FILTERED, and OPEN_FILTERED when above PRINT_LIMIT.
static void build_not_shown_str(u16 nb_closed, u16 nb_filtered,
								u16 nb_open_filtered)
{
	struct s_entry
	{
		u16			count;
		const char *label;
		const char *reason;
	} entries[3];
	u8 nb_entries = 0;

	if (nb_closed > 0)
	{
		entries[nb_entries].count = nb_closed;
		entries[nb_entries].label = "closed tcp";
		entries[nb_entries].reason = "reset";
		nb_entries++;
	}
	if (nb_filtered > 0)
	{
		entries[nb_entries].count = nb_filtered;
		entries[nb_entries].label = "filtered tcp";
		entries[nb_entries].reason = "no-response";
		nb_entries++;
	}
	if (nb_open_filtered > 0)
	{
		entries[nb_entries].count = nb_open_filtered;
		entries[nb_entries].label = "open|filtered tcp";
		entries[nb_entries].reason = "no-response";
		nb_entries++;
	}

	if (nb_entries == 0)
		return;

	printf("Not shown: ");
	for (u8 i = 0; i < nb_entries; i++)
	{
		if (i > 0)
			printf(", ");
		printf("%u %s port%s (%s)", entries[i].count, entries[i].label,
			   entries[i].count > 1 ? "s" : "", entries[i].reason);
	}
	printf("\n");
}

static void build_results_str(t_target *target, t_args *args, u16 port,
							  char *buf, size_t buf_size)
{
	char   scan_name[16];
	size_t offset = 0;

	for (u8 i = 0; i < args->nb_scan_types; i++)
	{
		t_scan_type	 stype = args->scan_types[i];
		u16			 idx = target->port_list.port_map[stype][port];
		t_port_state state
			= target->port_list.port_map_rev[stype][idx].port_state;

		scan_type_to_str(stype, scan_name);

		int written = snprintf(buf + offset, buf_size - offset, "%s(%s) ",
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
		int w = snprintf(NULL, 0, "%u/tcp", args->ports[i]);
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

	// ── Count states ─────────────────────────────────────────────────────────
	u16 nb_closed = 0;
	u16 nb_filtered = 0;
	u16 nb_open_filtered = 0;
	u16 nb_interesting = 0; // OPEN, UNFILTERED — never hidden

	for (u16 i = 0; i < args->port_count; i++)
	{
		t_port_state s = get_port_conclusion(target, args, args->ports[i]);
		if (s == CLOSE)
			nb_closed++;
		else if (s == FILTERED)
			nb_filtered++;
		else if (s == OPEN_FILTERED)
			nb_open_filtered++;
		if (!is_boring(s))
			nb_interesting++;
	}

	// ── "Not shown" block (only when above PRINT_LIMIT) ──────────────────────
	//
	// Below PRINT_LIMIT: too few ports to bother hiding anything → show all.
	// Above PRINT_LIMIT: hide boring states, show only interesting ones.
	// No cap on interesting ports: all OPEN/UNFILTERED are always displayed.
	const bool use_not_shown = (args->port_count > PRINT_LIMIT);

	if (use_not_shown)
	{
		if (nb_interesting == 0)
			printf("All %u scanned ports on %s are in ignored states.\n",
				   args->port_count, ip_str);
		build_not_shown_str(nb_closed, nb_filtered, nb_open_filtered);
	}

	// ── Protocol label ───────────────────────────────────────────────────────
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

	// ── Column header
	// ─────────────────────────────────────────────────────────
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

	// ── Rows
	// ──────────────────────────────────────────────────────────────────
	// use_not_shown  → skip boring states (hidden in "Not shown")
	// !use_not_shown → show every port (small scan, show everything)
	for (u16 i = 0; i < args->port_count; i++)
	{
		u16			 port = args->ports[i];
		t_port_state conclusion = get_port_conclusion(target, args, port);

		if (use_not_shown && is_boring(conclusion))
			continue;

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

	double elapsed
		= (double)(now.tv_sec - ctx->program_info.start.tv_sec)
		  + (double)(now.tv_usec - ctx->program_info.start.tv_usec) / 1e6;

	for (size_t i = 0; i < ctx->target_count; i++)
		print_target_results(&ctx->targets[i], &ctx->args);

	printf("\nft_nmap done: %zu IP address%s (%zu host%s up) scanned in %.2f "
		   "seconds\n",
		   ctx->target_count, ctx->target_count > 1 ? "es" : "",
		   ctx->target_count, ctx->target_count > 1 ? "s" : "", elapsed);
}
