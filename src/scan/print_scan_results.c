#include "debug.h"
#include "parsing.h"
#include "port_services.h"
#include "scan.h"
#include "utils.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PRINT_LIMIT 25
#define BUF_SIZE 4096

char *port_state_to_str(t_port_state state)
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
	case UNKNOWN:
		return "unknown";
	case DEFAULT:
		return "default";
	default:
		return NULL;
	}
}

static void update_port_reasons(t_port_output *port_conclusion,
								const t_port  *port)
{
	/* If the scan never produced a reason (e.g. probe was dropped before
	 * timeout could fire), there is nothing to merge. */
	if (port->reasons[0] == NULL)
		return;

	//  Same port state but maybe the reason the port is in that state is
	//  different
	if (port_conclusion->port_state == port->port_state)
	{
		if (port_conclusion->reasons[0] == NULL)
		{
			port_conclusion->reasons[0] = port->reasons[0];
		}
		else if (strcmp(port_conclusion->reasons[0], port->reasons[0]) != 0)
		{
			port_conclusion->reasons[1] = port->reasons[0];
		}
	}
	else
	{
		port_conclusion->reasons[0] = port->reasons[0];
		port_conclusion->reasons[1] = NULL;
	}
}

static void set_unknown_port_state(t_port_output *port_conclusion)
{
	port_conclusion->port_state = UNKNOWN;
	port_conclusion->reasons[0] = NULL;
	port_conclusion->reasons[1] = NULL;
}

/* Return true when we update the port state */
static void
update_definitive_port_state_and_reason(t_port_output *port_conclusion,
										const t_port  *port)
{
	if (port_conclusion->port_state == UNKNOWN)
	{
		port_conclusion->port_state = port->port_state;
		return;
	}
	switch (port->port_state)
	{
	case OPEN:
	case CLOSE:
		// If the TCP scans give irresolute result, we set the port's state to
		// UNKNOWN
		if ((port->port_state == CLOSE && port_conclusion->port_state == OPEN)
			|| (port->port_state == OPEN
				&& port_conclusion->port_state == CLOSE))
		{
			set_unknown_port_state(port_conclusion);
			return;
		}
		update_port_reasons(port_conclusion, port);
		port_conclusion->port_state = port->port_state;
		break;
	case OPEN_FILTERED:
		if (port_conclusion->port_state == DEFAULT
			|| port_conclusion->port_state == OPEN_FILTERED)
		{
			update_port_reasons(port_conclusion, port);
			port_conclusion->port_state = port->port_state;
		}
		if (port_conclusion->port_state == UNFILTERED
			|| port_conclusion->port_state == CLOSE)
		{
			set_unknown_port_state(port_conclusion);
		}
		break;
	case UNFILTERED:
		if (port_conclusion->port_state == UNFILTERED
			|| port_conclusion->port_state == DEFAULT)
		{
			update_port_reasons(port_conclusion, port);
			port_conclusion->port_state = port->port_state;
		}
		if (port_conclusion->port_state == FILTERED
			|| port_conclusion->port_state == OPEN_FILTERED)
		{
			set_unknown_port_state(port_conclusion);
		}
		break;
	case FILTERED:
		if (port_conclusion->port_state == OPEN
			|| port_conclusion->port_state == CLOSE)
		{
			set_unknown_port_state(port_conclusion);
		}
		else if (port_conclusion->port_state == OPEN_FILTERED
				 || port_conclusion->port_state == DEFAULT
				 || port_conclusion->port_state == FILTERED
				 || port_conclusion->port_state == UNFILTERED)
		{
			update_port_reasons(port_conclusion, port);
			port_conclusion->port_state = port->port_state;
		}
		break;
	default:
		break;
	}
}

// Ignored states are print from the most common to the least common and with a
// reason associated (no-response, reset, ...)
/* Count the number of ports in each state for a given protocol slot
 * (TCP_INDEX or UDP_INDEX), keeping TCP and UDP totals separate. */
static void count_states_for_proto(const t_target *target, u8 proto_index,
								   u16 port_count,
								   u16 counts[HIGHEST_PORT_STATE])
{
	for (u8 s = 0; s < HIGHEST_PORT_STATE; s++)
		counts[s] = 0;

	const t_port_output *arr = target->port_list.port_final_state[proto_index];
	if (arr == NULL)
		return;
	for (u16 i = 0; i < port_count; i++)
	{
		const t_port_state st = arr[i].port_state;
		if (st < HIGHEST_PORT_STATE)
			counts[st]++;
	}
}

/* Append one "Not shown" segment for a given (state, protocol) by walking the
 * state_and_reason linked list of that protocol and printing every reason
 * subtotal. */
static size_t
append_not_shown_segment(char *buf, size_t buf_size, size_t buf_len,
						 t_port_state_and_reason *head, t_port_state state,
						 const char *proto_str, bool *first_segment)
{
	for (t_port_state_and_reason *r = head; r != NULL; r = r->next)
	{
		if (r->port_state != state)
			continue;

		const char *state_str = port_state_to_str(state);

		/* tmp->reason == NULL means there are two sub-reasons stored in
		 * first_reason / second_reason. Print them both. */
		if (r->reason == NULL && r->first_reason && r->second_reason)
		{
			const char *r1
				= r->first_reason->reason ? r->first_reason->reason : "unknown";
			const char *r2 = r->second_reason->reason ? r->second_reason->reason
													  : "unknown";
			buf_len += snprintf(buf + buf_len, buf_size - buf_len,
								"%s%d %s %s ports (%s, %s)",
								*first_segment ? "" : ", ", r->count, state_str,
								proto_str, r1, r2);
		}
		else
		{
			const char *reason = r->reason ? r->reason : "unknown";
			buf_len
				+= snprintf(buf + buf_len, buf_size - buf_len,
							"%s%d %s %s ports (%s)", *first_segment ? "" : ", ",
							r->count, state_str, proto_str, reason);
		}
		*first_segment = false;
	}
	return buf_len;
}

/* Decide, per protocol, which states should be grouped into a "Not shown"
 * line. A state is grouped when it has strictly more than PRINT_LIMIT ports
 * in that protocol. TCP and UDP are treated independently, so we can group
 * e.g. closed-TCP without forcing the same on UDP.
 *
 * ignored_tcp / ignored_udp are output arrays indexed by t_port_state value
 * (size HIGHEST_PORT_STATE), set to true for states that should be hidden
 * from the per-port table.
 *
 * Returns true if every scanned port ended up in a grouped state (nothing
 * left to display in the detailed table). */
static bool print_ignored_port_states(const t_target *target, bool tcp_scan,
									  bool udp_scan, u16 port_count,
									  bool *ignored_tcp, bool *ignored_udp, bool verbose_mode)
{
	for (u8 s = 0; s < HIGHEST_PORT_STATE; s++)
	{
		ignored_tcp[s] = false;
		ignored_udp[s] = false;
	}

	u16 tcp_counts[HIGHEST_PORT_STATE] = { 0 };
	u16 udp_counts[HIGHEST_PORT_STATE] = { 0 };

	count_states_for_proto(target, TCP_INDEX, port_count, tcp_counts);
	count_states_for_proto(target, UDP_INDEX, port_count, udp_counts);

	char   buf[BUF_SIZE] = { 0 };
	size_t buf_len = 0;
	bool   first_segment = true;
	u16	   tcp_hidden = 0;
	u16	   udp_hidden = 0;

	for (t_port_state state = DEFAULT; state < HIGHEST_PORT_STATE; state++)
	{
		const bool tcp_group = tcp_scan && tcp_counts[state] > PRINT_LIMIT;
		const bool udp_group = udp_scan && udp_counts[state] > PRINT_LIMIT;

		if (!tcp_group && !udp_group)
			continue;

		// In verbose mode the 'Not shown' message is not relevant
		if (verbose_mode == false && first_segment)
		{
			buf_len = snprintf(buf, sizeof(buf), "Not shown: ");
		}

		if (tcp_group)
		{
			if (verbose_mode == false)
			{
				buf_len = append_not_shown_segment(
					buf, sizeof(buf), buf_len,
					target->port_list.state_and_reason[TCP_INDEX], state, "tcp",
					&first_segment);
			}

			ignored_tcp[state] = true;
			tcp_hidden += tcp_counts[state];
		}
		if (udp_group)
		{
			if (verbose_mode == false)
			{
				buf_len = append_not_shown_segment(
					buf, sizeof(buf), buf_len,
					target->port_list.state_and_reason[UDP_INDEX], state, "udp",
					&first_segment);
			}
			ignored_udp[state] = true;
			udp_hidden += udp_counts[state];
		}
	}

	const u16  tcp_total = tcp_scan ? port_count : 0;
	const u16  udp_total = udp_scan ? port_count : 0;
	const bool all_ignored
		= (tcp_total + udp_total) > 0
		  && (tcp_hidden + udp_hidden) == (tcp_total + udp_total);

	if (buf_len > 0)
	{
		printf("%s\n", buf);
	}
	else if (tcp_total + udp_total == 0)
	{
		/* Nothing to show at all (no scan ran). */
		printf("All %u scanned ports on %s are in ignored states.\n",
			   port_count, target->input);
		return true;
	}
	return all_ignored;
}

static void build_results_str(const t_target *target, const t_args *args,
							  const u16 port, char *buf, size_t buf_size,
							  u8 protocol)
{
	char   scan_name[16];
	size_t offset = 0;

	for (u8 i = 0; i < args->nb_scan_types; i++)
	{
		const t_scan_type stype = args->scan_types[i];
		if (stype == SCAN_UDP && protocol != IPPROTO_UDP)
			continue;
		const int		   idx = target->port_list.port_map[port];
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
int compute_port_col_width(const t_args *args)
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

int find_or_update_state_and_reason_combination(
	t_port_state_and_reason **state_and_reason_lst, t_port_state port_state,
	const char *reason)
{
	t_port_state_and_reason *tmp = *state_and_reason_lst;
	t_port_state_and_reason *prev = NULL;
	/* If no reason was ever attached to this port (state stayed DEFAULT,
	 * timeout never fired, etc.) fall back to a placeholder so that NULL
	 * never reaches strcmp below. */
	if (reason == NULL)
		reason = "unknown";
	if (tmp == NULL)
	{
		*state_and_reason_lst = calloc(1, sizeof(t_port_state_and_reason));
		if (*state_and_reason_lst == NULL)
		{
			LOG("ft_nmap: calloc failed: %s\n", strerror(errno));
			return FAILURE;
		}
		(*state_and_reason_lst)->reason = reason;
		(*state_and_reason_lst)->count = 1;
		(*state_and_reason_lst)->port_state = port_state;
		(*state_and_reason_lst)->next = NULL;
		(*state_and_reason_lst)->first_reason = NULL;
		(*state_and_reason_lst)->second_reason = NULL;
		return SUCCESS;
	}
	while (tmp)
	{
		if (port_state == tmp->port_state)
		{
			// Either the reason match, either this is different reason so we
			// filled the sub nodes

			// If reason is NULL it means there are two reasons (check subnodes)
			if (tmp->reason == NULL)
			{
				if (tmp->first_reason && tmp->first_reason->reason
					&& strcmp(tmp->first_reason->reason, reason) == 0)
				{
					tmp->first_reason->count++;
				}
				else if (tmp->second_reason && tmp->second_reason->reason
						 && strcmp(tmp->second_reason->reason, reason) == 0)
				{
					tmp->second_reason->count++;
				}
				return SUCCESS;
			}
			else
			{
				if (strcmp(tmp->reason, reason) == 0)
				{
					tmp->count++;
					return SUCCESS;
				}
				else
				{
					tmp->first_reason
						= calloc(1, sizeof(t_port_state_and_reason));
					if (tmp->first_reason == NULL)
					{
						LOG("ft_nmap: calloc failed: %s\n", strerror(errno));
						return FAILURE;
					}
					tmp->second_reason
						= calloc(1, sizeof(t_port_state_and_reason));
					if (tmp->second_reason == NULL)
					{
						LOG("ft_nmap: calloc failed: %s\n", strerror(errno));
						return FAILURE;
					}

					// Copy from parent node to first child node
					tmp->first_reason->count = tmp->count;
					tmp->first_reason->reason = tmp->reason;

					// This will now track the total count (both reasons)
					tmp->count++;
					tmp->reason = NULL;

					tmp->second_reason->count = 1;
					tmp->second_reason->reason = reason;
				}
				return SUCCESS;
			}
		}
		prev = tmp;
		tmp = tmp->next;
	}
	// The port state - reason is not registered so we store it
	prev->next = calloc(1, sizeof(t_port_state_and_reason));
	if (prev->next == NULL)
	{
		LOG("ft_nmap: calloc failed: %s\n", strerror(errno));
		return FAILURE;
	}

	prev->next->reason = reason;
	prev->next->count = 1;
	prev->next->port_state = port_state;
	return SUCCESS;
}

static bool is_ignored_state(const bool	 *ignored_states_by_idx,
							 t_port_state port_state)
{
	if (port_state >= HIGHEST_PORT_STATE)
		return false;
	return ignored_states_by_idx[port_state];
}

static void resolve_final_port_state(const t_args *args, t_target *target)
{
	for (u16 i = 0; i < args->port_count; i++)
	{
		const int idx = target->port_list.port_map[args->ports[i]];

		for (u8 j = 0; j < args->nb_scan_types; j++)
		{
			const t_scan_type scan_type_index = args->scan_types[j];
			const u8		  protocol_index
				= (scan_type_index == SCAN_UDP) ? UDP_INDEX : TCP_INDEX;

			/* Update the conclusion of a port state based off what each scan
				type gave us */

			update_definitive_port_state_and_reason(
				&target->port_list.port_final_state[protocol_index][idx],
				&target->port_list.port_map_rev[scan_type_index][idx]);
		}
		if (args->tcp_scan)
		{
			t_port_output target_port_output
				= target->port_list.port_final_state[TCP_INDEX][idx];
			t_port_state target_port_state = target_port_output.port_state;

			/* Keep track of the occurences of each port state (OPEN, FILTERED,
			 ...) with their associated reason */
			find_or_update_state_and_reason_combination(
				&target->port_list.state_and_reason[TCP_INDEX],
				target_port_state, target_port_output.reasons[0]);

			// Second reason can be empty
			if (target->port_list.port_final_state[TCP_INDEX][idx].reasons[1]
				!= NULL)
			{
				find_or_update_state_and_reason_combination(
					&target->port_list.state_and_reason[TCP_INDEX],
					target_port_state, target_port_output.reasons[1]);
			}
		}

		if (args->udp_scan)
		{
			// Since there's only one UDP scan available the port can only be in
			// a state for a single reason
			t_port_output target_port_output
				= target->port_list.port_final_state[UDP_INDEX][idx];
			t_port_state target_port_state = target_port_output.port_state;

			find_or_update_state_and_reason_combination(
				&target->port_list.state_and_reason[UDP_INDEX],
				target_port_state, target_port_output.reasons[0]);
		}
	}
}

static void print_port_states(const t_target *target, const t_args *args,
							  const bool *ignored_tcp, const bool *ignored_udp)
{
	char recap_udp[65535] = { 0 };
	char recap_tcp[65535] = { 0 };

	const int col_port = compute_port_col_width(args);
	const int col_state = 14;
	const int col_svc = 20;
	const int col_version = 28;

	static u8 nb_scan_type_tcp = 0;
	if (nb_scan_type_tcp == 0)
	{
		for (u8 i = 0; i < args->nb_scan_types; i++)
		{
			if (args->scan_types[i] != SCAN_UDP)
			{
				nb_scan_type_tcp++;
			}
		}
	}
	const int col_scan_result
		= (args->nb_scan_types == 1 || nb_scan_type_tcp == 1)
			  ? 18
			  : nb_scan_type_tcp * 14;
	const int col_reason = 12;

	const bool multi_scan_tcp = nb_scan_type_tcp > 1;
	const bool show_version = HAS(args->flags, F_VERSION) && args->tcp_scan;

	// Multi scan is only usefull for tcp, but we put it also for UDP because
	// otherwise we have an empty column when mixing UDP,TCP scan
	printf("%-*s %-*s %-*s %-*s", col_port, "PORT", col_state, "STATE", col_svc,
		   "SERVICE", multi_scan_tcp ? col_scan_result : 0,
		   multi_scan_tcp ? "SCAN RESULTS" : "");
	if (HAS(args->flags, F_REASON))
		printf("%-*s", col_reason, "REASON");
	if (show_version)
		printf(" %s", "VERSION");
	printf("\n");

	// For each port we check that his state is not among the "ignored states"
	// which are all the state with more than 25 ports in If thats not the case
	// we add a row to the table
	for (u16 port = MIN_PORT_NUMBER; port <= args->max_port_nb; port++)
	{
		const int idx = target->port_list.port_map[port];

		if (idx == -1)
			continue;

		if (args->udp_scan
			&& (is_ignored_state(
					ignored_udp,
					target->port_list.port_final_state[UDP_INDEX][idx]
						.port_state)
					== false
				|| HAS(args->flags, F_VERBOSE)))
		{
			t_port_output final_port_state
				= target->port_list.port_final_state[UDP_INDEX][idx];
			char port_str[16];
			snprintf(port_str, sizeof(port_str), "%u/udp", port);

			const char *svc
				= port_services_udp[port] ? port_services_udp[port] : "unknown";

			const char *state = port_state_to_str(final_port_state.port_state);

			size_t recap_udp_len = strlen(recap_udp);

			char results_buf[256];
			snprintf(results_buf, sizeof(results_buf), "%s(%s)", "UDP", state);

			snprintf(recap_udp + recap_udp_len,
					 sizeof(recap_udp) - recap_udp_len, "%-*s %-*s %-*s %-*s",
					 col_port, port_str, col_state, state, col_svc,
					 svc ? svc : "unknown",
					 multi_scan_tcp ? col_scan_result : 0, "");
			recap_udp_len = strlen(recap_udp);

			if (HAS(args->flags, F_REASON))
			{
				snprintf(recap_udp + recap_udp_len,
						 sizeof(recap_udp) - recap_udp_len, "%-*s", col_reason,
						 final_port_state.reasons[0]);
				recap_udp_len = strlen(recap_udp);
			}
			snprintf(recap_udp + recap_udp_len,
					 sizeof(recap_udp) - recap_udp_len, "\n");
		}
		if (args->tcp_scan
			&& (is_ignored_state(
					ignored_tcp,
					target->port_list.port_final_state[TCP_INDEX][idx]
						.port_state)
					== false
				|| HAS(args->flags, F_VERBOSE)))
		{
			const char *svc
				= port_services_tcp[port] ? port_services_tcp[port] : "unknown";

			t_port_output final_port_state
				= target->port_list.port_final_state[TCP_INDEX][idx];
			char port_str[16];
			snprintf(port_str, sizeof(port_str), "%u/tcp", port);
			const char *state = port_state_to_str(
				target->port_list.port_final_state[TCP_INDEX][idx].port_state);
			const char *ver = (show_version && final_port_state.version[0])
								  ? final_port_state.version
								  : "";
			size_t		recap_tcp_len = strlen(recap_tcp);
			if (multi_scan_tcp)
			{
				char results_buf[256];
				build_results_str(target, args, port, results_buf,
								  sizeof(results_buf), IPPROTO_TCP);
				snprintf(recap_tcp + recap_tcp_len,
						 sizeof(recap_tcp) - recap_tcp_len,
						 "%-*s %-*s %-*s %-*s%s%s", col_port, port_str,
						 col_state, state, col_svc, svc ? svc : "unknown",
						 col_scan_result, results_buf,
						 (show_version && ver[0]) ? "  " : "", ver);

				recap_tcp_len = strlen(recap_tcp);

				// Print reason for each type of scan ran
				if (HAS(args->flags, F_REASON))
				{
					const int	idx = target->port_list.port_map[port];
					const char *first_reason
						= target->port_list.port_final_state[TCP_INDEX][idx]
							  .reasons[0];
					const char *second_reason
						= target->port_list.port_final_state[TCP_INDEX][idx]
							  .reasons[1];

					char	   *reasons_alloc = NULL;
					const char *reasons = NULL;

					if (first_reason && second_reason)
					{
						const size_t len_first = strlen(first_reason);
						const size_t len_second = strlen(second_reason);

						reasons_alloc
							= calloc(len_first + len_second + 3, sizeof(char));
						if (reasons_alloc == NULL)
						{
							LOG("ft_nmap: calloc failed: %s\n",
								strerror(errno));
							continue;
						}
						snprintf(reasons_alloc, len_first + len_second + 3,
								 "%s, %s", first_reason, second_reason);
						reasons = reasons_alloc;
					}
					else if (second_reason == NULL)
					{
						reasons = first_reason ? first_reason : "";
					}
					else
					{
						reasons = second_reason ? second_reason : "";
					}
					snprintf(recap_tcp + recap_tcp_len,
							 sizeof(recap_tcp) - recap_tcp_len, " %-*s",
							 col_reason, reasons);

					recap_tcp_len = strlen(recap_tcp);
					free(reasons_alloc);
				}
				recap_tcp_len = strlen(recap_tcp);
				snprintf(recap_tcp + recap_tcp_len,
						 sizeof(recap_tcp) - recap_tcp_len, "\n");
			}
			else
			{
				snprintf(recap_tcp + recap_tcp_len,
						 sizeof(recap_tcp) - recap_tcp_len, "%-*s %-*s %-*s",
						 col_port, port_str, col_state, state, col_svc,
						 svc ? svc : "unknown");
				recap_tcp_len = strlen(recap_tcp);
				if (HAS(args->flags, F_REASON))
				{
					snprintf(recap_tcp + recap_tcp_len,
							 sizeof(recap_tcp) - recap_tcp_len, " %-*s",
							 col_reason,
							 final_port_state.reasons[0]
								 ? final_port_state.reasons[0]
								 : "");
					recap_tcp_len = strlen(recap_tcp);
				}
				if (show_version && ver[0])
				{
					snprintf(recap_tcp + recap_tcp_len,
							 sizeof(recap_tcp) - recap_tcp_len, " %-*s",
							 col_version, ver);
					recap_tcp_len = strlen(recap_tcp);
				}
				snprintf(recap_tcp + recap_tcp_len,
						 sizeof(recap_tcp) - recap_tcp_len, "\n");
			}
		}
	}
	if (args->tcp_scan)
	{
		sync_printf("%s", recap_tcp);
	}
	if (args->udp_scan)
	{
		sync_printf("%s\n", recap_udp);
	}
}

static void print_target_results(t_target *target, const t_args *args)
{
	/* Per-protocol "is this state hidden in Not shown ?" lookup tables.
	 * Indexed by t_port_state value. We need two tables because a state
	 * may dominate one protocol but not the other (e.g. 100 closed-TCP +
	 * 5 closed-UDP — closed should be grouped for TCP, listed for UDP). */
	bool ignored_tcp[HIGHEST_PORT_STATE] = { 0 };
	bool ignored_udp[HIGHEST_PORT_STATE] = { 0 };

	/* Header: show "hostname (IP)" when reverse DNS found something,
	 * otherwise fall back to whatever the user typed. */
	const char *ip_str = inet_ntoa(target->addr);
	if (target->hostname && strcmp(target->hostname, target->input) != 0)
	{
		printf("Nmap scan report for %s (%s)\n", target->hostname, ip_str);
	}
	else
	{
		printf("Nmap scan report for %s\n", target->input);
	}
	printf("Host is up.\n");

	/* OS detection: display below "Host is up" if --os-detect and we have
	 * data
	 */
	if (HAS(args->flags, F_OS_DETECT))
	{
		if (target->os_ttl != 0)
		{
			printf("OS: %s\n", guess_os(target->os_ttl, target->os_tcp_window));
		}
		else
		{
			printf("OS: Detection requires at least one open TCP port (SYN "
				   "scan)\n");
		}
	}

	resolve_final_port_state(args, target);

	/* Version detection: banner-grab every open TCP port before printing */
	if (HAS(args->flags, F_VERSION))
	{
		grab_versions(target, args);
	}

	const bool all_ignored
		= print_ignored_port_states(target, args->tcp_scan, args->udp_scan,
									args->port_count, ignored_tcp, ignored_udp, HAS(args->flags, F_VERBOSE));

	if (HAS(args->flags, F_VERBOSE) || all_ignored == false)
	{
		print_port_states(target, args, ignored_tcp, ignored_udp);
	}
}

void print_scan_results(t_ctx *ctx)
{
	struct timeval now;
	if (gettimeofday(&now, NULL) == -1)
	{
		LOG("ft_nmap: gettimeofday failed: %s\n", strerror(errno));
		return;
	}

	const double elapsed
		= (double)(now.tv_sec - ctx->program_info.start.tv_sec)
		  + (double)(now.tv_usec - ctx->program_info.start.tv_usec) / 1e6;
	for (size_t i = 0; i < ctx->target_count; i++)
	{
		print_target_results(&ctx->targets[i], &ctx->args);
	}

	printf("\nft_nmap done: %zu IP address%s (%zu host%s up) scanned in %.2f "
		   "seconds\n",
		   ctx->target_count, ctx->target_count > 1 ? "es" : "",
		   ctx->target_count, ctx->target_count > 1 ? "s" : "", elapsed);
}
