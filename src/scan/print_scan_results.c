#include "debug.h"
#include "scan.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PRINT_LIMIT 25
#define BUF_SIZE 4096

// ── Helpers
// ───────────────────────────────────────────────────────────────────

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

// const char *port_state_color(t_port_state state)
// {
// 	switch (state)
// 	{
// 	case OPEN:
// 		return ANSI_COLOR_GREEN;
// 	case FILTERED:
// 		return ANSI_COLOR_YELLOW;
// 	case OPEN_FILTERED:
// 		return ANSI_COLOR_YELLOW;
// 	case UNFILTERED:
// 		return ANSI_COLOR_CYAN;
// 	case CLOSE:
// 		return ANSI_COLOR_RED;
// 	default:
// 		return ANSI_COLOR_RESET;
// 	}
// }

const char *get_service_name(u16 port)
{
	const struct servent *svc = getservbyport(htons(port), "tcp");
	if (svc)
		return svc->s_name;
	svc = getservbyport(htons(port), "udp");
	if (svc)
		return svc->s_name;
	return "unknown";
}

static void update_port_reasons(t_port_output *port_conclusion,
								const t_port  *port)
{
	//  Same port state but maybe the reason the port is in that state is
	//  different
	if (port_conclusion->port_state == port->port_state)
	{
		assert(port->reasons[0] != NULL);
		if (strcmp(port_conclusion->reasons[0], port->reasons[0]) != 0)
		{
			port_conclusion->reasons[1] = port->reasons[0];
		}
	}
	else
	{
		// printf("%s\n", port_state_to_str(port->port_state));
		assert(port->reasons[0] != NULL);
		assert(port->reasons[1] == NULL);
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
	// fprintf(stderr, "port conclusion: %s\n",
	// 		port_state_to_str(port->port_state));
	// fprintf(stderr, "port state: %s\n",
	// 		port_state_to_str(port_conclusion->port_state));
	if (port_conclusion->port_state == UNKNOWN)
	{
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

// Determine overall conclusion for a port across all scan types.
//
// We check for OPEN and CLOSE status first because it gives a definitive
// answer:
//   - SYN → OPEN  (SYN-ACK): return immediately, no ambiguity.
//   - SYN, XMAS, URG, NULL and UDP → CLOSE (RST): return immediately, no
//   ambiguity.
// We also need to retrieve the reason associated with that state (both for UDP
// and TCP) Also for TCP there can be two reason given for a port to be
// UNFILTERED for example (unreachable or no-response) depending on the type of
// scan

// static void get_port_conclusion(const t_target *target, const t_args *args,
// 								t_port *port, t_port_output *port_conclusion)
// {
// 	(void)target;
// 	for (u8 i = 0; i < args->nb_scan_types; i++)
// 	{
// 		const t_scan_type scan_type = args->scan_types[i];

// 		// Index of the port inside all port_map_rev arrays (one for each scan
// 		// types) port map act as a presence table
// 		// const u16 idx = target->port_list.port_map[port];

// 		// const t_port *port = &target->port_list.port_map_rev[scan_type][idx];
// 		if (scan_type == SCAN_UDP)
// 		{
// 			port_conclusion->port_number = port->port_number;
// 			update_definitive_port_state_and_reason(port_conclusion, port);
// 		}
// 		else
// 		{
// 			port_conclusion->port_number = port->port_number;
// 			update_definitive_port_state_and_reason(port_conclusion, port);
// 		}
// 	}
// }

// static bool port_state_already_ignored(u8 *previous_ignored_port_states,
// 									   u8  port_state)
// {
// 	for (u8 k = 0; k < HIGHEST_PORT_STATE; k++)
// 	{
// 		if (previous_ignored_port_states[k] == port_state)
// 		{
// 			return true;
// 			continue;
// 		}
// 	}
// 	return false;
// }

/* Return true and filled next_ignored_port_state (which have the highest number
of port in this state accross both protocol TCP and UDP) or false if no ignored
state are left */
bool get_next_ignored_port_state(int		  *state_count,
								 t_port_state *next_ignored_state)
{
	static t_port_state previous_ignored_port_state = UNKNOWN;
	u16					max = PRINT_LIMIT;
	u16 max_prev_ignored_port_state = state_count[previous_ignored_port_state];

	for (t_port_state i = DEFAULT; i < UNKNOWN; i++)
	{
		if (state_count[i] > max)
		{
			if (previous_ignored_port_state != DEFAULT)
			{
				if (state_count[i] > max_prev_ignored_port_state)
					continue;
			}
			max = state_count[i];
			*next_ignored_state = i;
		}
	}
	bool ret = previous_ignored_port_state != *next_ignored_state;
	previous_ignored_port_state = *next_ignored_state;
	return ret;
}

// Return true and filled next_ignored_port_state_reason with the reason /
// occurences associated with the ignored port state given
bool get_reason_for_port_state(
	t_port_state_and_reason **head,
	t_port_state_and_reason	 *next_ignored_port_state_reason,
	t_port_state			  ignored_port_state)
{
	t_port_state_and_reason *tmp = *head;
	t_port_state_and_reason *prev = NULL;

	while (tmp)
	{
		if (tmp->port_state == ignored_port_state)
		{
			memcpy(next_ignored_port_state_reason, tmp,
				   sizeof(t_port_state_and_reason));
			// erase node
			if (prev)
			{
				prev->next = tmp->next;
			}
			else
			{
				*head = tmp->next;
			}
			return true;
		}
		prev = tmp;
		tmp = tmp->next;
	}

	return false;
}

char *state_to_label(t_port_state state)
{
	switch (state)
	{
	case DEFAULT:
		return "default";
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

// Ignored states are print from the most common to the least common and with a
// reason associated (no-response, reset, ...)
static bool print_ignored_port_states(t_target *target, bool tcp_scan,
									  bool udp_scan, u16 port_count,
									  t_port_state *ignored_port_states)
{
	(void)ignored_port_states;
	bool					display_not_shown_str = false;
	t_port_state_and_reason next_ignored_port_state_reason = { 0 };
	t_port_state			next_ignored_port_state = { UNKNOWN };
	int						i = 0;
	bool					all_ignored = false;

	char buf[BUF_SIZE] = { 0 };
	while (get_next_ignored_port_state(target->port_list.state_count,
									   &next_ignored_port_state))
	{
		const char *port_state_str = port_state_to_str(next_ignored_port_state);

		if (tcp_scan)
		{
			while (get_reason_for_port_state(
				&target->port_list.state_and_reason[TCP_INDEX],
				&next_ignored_port_state_reason, next_ignored_port_state))
			{
				if (display_not_shown_str == false)
				{
					snprintf(buf, sizeof(buf), "Not shown: ");
					display_not_shown_str = true;
				}

				size_t buf_len = strlen(buf);
				if (next_ignored_port_state_reason.first_reason != NULL)
				{
					snprintf(
						buf + buf_len, sizeof(buf) - buf_len,
						"%d %s tcp ports (%s)",
						next_ignored_port_state_reason.second_reason->count,
						port_state_str,
						next_ignored_port_state_reason.second_reason->reason);
					if (next_ignored_port_state_reason.second_reason != NULL)
					{
						size_t buf_len = strlen(buf);
						snprintf(
							buf + buf_len, sizeof(buf) - buf_len,
							", %d %s tcp ports (%s)",
							next_ignored_port_state_reason.second_reason->count,
							port_state_str,
							next_ignored_port_state_reason.second_reason
								->reason);
					}
				}
				else
				{
					snprintf(buf + buf_len, sizeof(buf) - buf_len,
							 "%d %s tcp ports (%s)\n",
							 next_ignored_port_state_reason.count,
							 port_state_str,
							 next_ignored_port_state_reason.reason);
				}
			}
		}
		if (udp_scan)
		{
			while (get_reason_for_port_state(
				&target->port_list.state_and_reason[UDP_INDEX],
				&next_ignored_port_state_reason, next_ignored_port_state))
			{
				if (display_not_shown_str == false)
				{
					snprintf(buf, sizeof(buf), "Not shown: ");
					display_not_shown_str = true;
				}
				size_t buf_len = strlen(buf);
				snprintf(buf + buf_len, sizeof(buf) - buf_len,
						 "%d %s udp ports (%s)\n",
						 next_ignored_port_state_reason.count, port_state_str,
						 next_ignored_port_state_reason.reason);
			}
		}
		ignored_port_states[i++] = next_ignored_port_state;
	}
	if (target->port_list.state_and_reason[TCP_INDEX] == NULL
		&& target->port_list.state_and_reason[UDP_INDEX] == NULL)
	{
		printf("All %u scanned ports on %s are in ignored states.\n",
			   port_count, target->input);
		all_ignored = true;
	}
	printf("%s", buf);
	return all_ignored;
}
// 	t_port_state next_ignore_state = get_next_ignored_state(state_count);
// 	(void)tcp_scan;
// 	(void)udp_scan;
// 	(void)port_count;
// 	// struct s_entry
// 	// {
// 	// 	u16			count;
// 	// 	const char *label;
// 	// 	const char *reason;
// 	// } entries[3];
// 	// u8 nb_entries = 0;

// 	if (next_ignore_state != UNKNOWN)
// 	{
// 		printf("Not shown: ");
// 	}
// 	char reasons[2][16] = { 0 };
// 	while (next_ignore_state != UNKNOWN)
// 	{
// 		char *state_label = state_to_label(next_ignore_state);
// 		int	  count = state_count[next_ignore_state];
// 		/* sub count for first reason */
// 		int sub_count_1 = 0;
// 		int sub_count_2 = 0;
// 		if (tcp_scan)
// 		{
// 			get_common_reason(port_final_state[TCP], port_count, reasons[0],
// 							  &sub_count_1);
// 			/* If we have more than two reason
// 			Ex: Half the port were filtered because 'no-response' and the other
// half because we got icmp error code */
// 			if (sub_count_1 == count)
// 			{
// 				printf("%u %s tcp port%s (%s)", count, state_label,
// 					   count > 1 ? "s" : "", reasons[0]);
// 			}
// 			else
// 			{
// 				get_common_reason(port_final_state[0], port_count, reasons[1],
// 								  &sub_count_2);
// 				printf("%u %s tcp port%s (%s), %u %s tcp port%s
// 					   (% s) ", sub_count_1, state_label, sub_count_1 > 1 ? " s
// 							 " : "
// 							 ", reasons[0],
// 					   sub_count_2,
// 					   state_label, sub_count_2 > 1 ? "s" : "", reasons[1]);
// 			}
// 		}
// 		// If we got both tcp scan and udp we need to separate the output like
// 	so:
// 		// Not shown: 16 open|filtered udp ports (no-response), 16 open|filtered
// 		tcp ports(no - response) if (udp_scan)
// 		{
// 			memset(reasons, 0, sizeof(reasons));
// 			if (tcp_scan)
// 			{
// 				printf(", ");
// 			}
// 			get_common_reason(port_final_state[1], port_count, reasons[0],
// 							  &sub_count_1);
// 			/* If we have more than two reason
// 				Ex: Not shown: 16 open|filtered udp ports (no-response), 16
// open|filtered udp ports (icmp-unreachable-error) */
// 			if (sub_count_1 == count)
// 			{
// 				printf("%u %s udp port%s (%s)\n", count, state_label,
// 					   count > 1 ? "s" : "", reasons[0]);
// 			}
// 			else
// 			{
// 				get_common_reason(port_final_state[1], port_count, reasons[1],
// 								  &sub_count_2);
// 				printf("%u %s udp port%s (%s), %u udp port%s
// 					   (% s) ", sub_count_1, state_label, sub_count_1 > 1 ? " s
// 							 " : "
// 							 ", reasons[0],
// 					   sub_count_2,
// 					   state_label, sub_count_2 > 1 ? "s" : "", reasons[1]);
// 			}
// 		}
// 		printf("\n");
// 		next_ignore_state = get_next_ignored_state(state_count);
// 	}
// }

// if (nb_closed > 0)
// {
// 	nb_entries++;
// }
// if (nb_filtered > 0)
// {
// 	entries[nb_entries].count = nb_filtered;
// 	entries[nb_entries].label = "filtered tcp";
// 	entries[nb_entries].reason = "no-response";
// 	nb_entries++;
// }
// if (nb_open_filtered > 0)
// {
// 	entries[nb_entries].count = nb_open_filtered;
// 	entries[nb_entries].label = "open|filtered tcp";
// 	entries[nb_entries].reason = "no-response";
// 	nb_entries++;
// }

// if (nb_entries == 0)
// 	return;

// printf("Not shown: ");
// for (u8 i = 0; i < nb_entries; i++)
// {
// 	if (i > 0)
// 		printf(", ");
// 	printf("%u %s port%s (%s)", entries[i].count, entries[i].label,
// 		   entries[i].count > 1 ? "s" : "", entries[i].reason);
// }
// printf("\n");
// }

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
		if (stype != SCAN_UDP && protocol == IPPROTO_UDP)
			continue;
		const int		   idx = target->port_list.port_map[PORT(port)];
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
int compute_port_col_width(t_args *args)
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

bool find_or_update_state_and_reason_combination(
	t_port_state_and_reason **state_and_reason_lst, t_port_state port_state,
	char *reason)
{
	t_port_state_and_reason *tmp = *state_and_reason_lst;
	t_port_state_and_reason *prev = NULL;
	if (tmp == NULL)
	{
		*state_and_reason_lst = calloc(1, sizeof(t_port_state_and_reason));
		(*state_and_reason_lst)->reason = reason;
		(*state_and_reason_lst)->count = 1;
		(*state_and_reason_lst)->port_state = port_state;
		(*state_and_reason_lst)->next = NULL;
		(*state_and_reason_lst)->first_reason = NULL;
		(*state_and_reason_lst)->second_reason = NULL;
		return false;
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
				// TODO: uncomment
				//  assert(tmp->first_reason != NULL);
				//  assert(tmp->first_reason->reason != NULL);
				// assert(reason != NULL);
				if (strcmp(tmp->first_reason->reason, reason) == 0)
				{
					tmp->first_reason->count++;
				}
				else if (tmp->second_reason->reason
						 && strcmp(tmp->second_reason->reason, reason) == 0)
				{
					tmp->second_reason->count++;
				}
				return false;
			}
			else
			{
				if (strcmp(tmp->reason, reason) == 0)
				{
					tmp->count++;
					return false;
				}
				else
				{
					tmp->first_reason
						= calloc(1, sizeof(t_port_state_and_reason));
					if (tmp->first_reason == NULL)
					{
						LOG("ft_nmap: calloc failed: %s\n", strerror(errno));
						return true;
					}
					tmp->second_reason
						= calloc(1, sizeof(t_port_state_and_reason));
					if (tmp->second_reason == NULL)
					{
						LOG("ft_nmap: calloc failed: %s\n", strerror(errno));
						return true;
					}

					// Copy from parent node to first child node
					tmp->first_reason->count = tmp->count;
					tmp->first_reason->reason = tmp->reason;
					if (tmp->first_reason == NULL)
					{
						printf("%s\n", port_state_to_str(tmp->port_state));
						exit(EXIT_FAILURE);
					}

					// This will now track the total count (both reasons)
					tmp->count++;
					tmp->reason = NULL;

					tmp->second_reason->count = 1;
					tmp->second_reason->reason = reason;
				}
				return false;
			}
		}
		prev = tmp;
		tmp = tmp->next;
	}
	// The port state - reason is not registered so we store it
	prev->next = calloc(1, sizeof(t_port_state_and_reason));
	prev->next->reason = reason;
	prev->next->count = 1;
	prev->next->port_state = port_state;
	return false;
}

static bool is_ignored_state(t_port_state *ignored_port_states,
							 t_port_state  port_state)
{
	for (u8 i = 0; i < HIGHEST_PORT_STATE; i++)
	{
		if (port_state == ignored_port_states[i])
		{
			return true;
		}
	}
	return false;
}

static void resolve_final_port_state(t_args *args, t_target *target)
{
	for (u16 i = 0; i < args->port_count; i++)
	{
		const int idx = target->port_list.port_map[PORT(args->ports[i])];
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
			// The port count in each port state is global between UDP and TCP
			target->port_list.state_count[target_port_state]++;
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

			target->port_list.state_count[target_port_state]++;
		}
	}
}

static void print_port_states(t_target *target, t_args *args,
							  t_port_state *ignored_port_states)
{
	char recap_udp[65535] = { 0 };
	char recap_tcp[65535] = { 0 };

	const int  col_port = compute_port_col_width(args);
	const int  col_state = 14;
	const int  col_svc = 10;
	const int  col_reason = 12;
	const bool multi_scan = args->nb_scan_types > 1;

	if (multi_scan)
	{
		printf("%-*s %-*s %-*s %s ", col_port, "PORT", col_state, "STATE",
			   col_svc, "SERVICE", "SCAN RESULTS");
		if (HAS(args->flags, F_REASON))
		{
			printf(" %-*s", col_reason, "REASON");
		}
		printf("\n");
	}
	else
	{
		printf("%-*s %-*s %-*s", col_port, "PORT", col_state, "STATE", col_svc,
			   "SERVICE");
		if (HAS(args->flags, F_REASON))
		{
			printf(" %-*s", col_reason, "REASON");
		}
		printf("\n");
	}
	// For each port we check that his state is not among the "ignored states"
	// which are all the state with more than 25 ports in If thats not the case
	// we add a row to the table

	for (u16 port = 1024; port <= args->max_port_nb; port++)
	{
		// const u16 port = args->ports[i];
		const int idx = target->port_list.port_map[PORT(port)];

		if (idx == -1)
			continue;

		if (args->udp_scan
			&& is_ignored_state(
				   ignored_port_states,
				   target->port_list.port_final_state[UDP_INDEX][idx]
					   .port_state)
				   == false)
		{
			t_port_output final_port_state
				= target->port_list.port_final_state[UDP_INDEX][idx];
			char port_str[16];
			snprintf(port_str, sizeof(port_str), "%u/udp", port);

			const char *svc = get_service_name(port);
			// const char *color = port_state_color(final_port_state.port_state);
			const char *state = port_state_to_str(final_port_state.port_state);

			size_t recap_udp_len = strlen(recap_udp);
			if (multi_scan)
			{
				char results_buf[256];
				build_results_str(target, args, port, results_buf,
								  sizeof(results_buf), IPPROTO_UDP);
snprintf(recap_udp + recap_udp_len,
         sizeof(recap_udp) - recap_udp_len,
         "%-*s %-*s %-*s %s\n", col_port, port_str,
         col_state, state, col_svc, svc,
         results_buf);
			}
			else
			{
snprintf(recap_udp + recap_udp_len,
         sizeof(recap_udp) - recap_udp_len,
         "%-*s %-*s %-*s", col_port, port_str,
         col_state, state, col_svc, svc);
				recap_udp_len = strlen(recap_udp);
				if (HAS(args->flags, F_REASON))
				{
					snprintf(recap_udp + recap_udp_len,
							 sizeof(recap_udp) - recap_udp_len, " %-*s",
							 col_reason, final_port_state.reasons[0]);
				}
				recap_udp_len = strlen(recap_udp);
				snprintf(recap_udp + recap_udp_len,
						 sizeof(recap_udp) - recap_udp_len, "\n");
			}
		}
		if (args->tcp_scan
			&& is_ignored_state(
				   ignored_port_states,
				   target->port_list.port_final_state[TCP_INDEX][idx]
					   .port_state)
				   == false)
		{
			t_port_output final_port_state
				= target->port_list.port_final_state[TCP_INDEX][idx];
			char port_str[16];
			snprintf(port_str, sizeof(port_str), "%u/tcp", port);
			const char *svc = get_service_name(port);
			// const char *color = port_state_color(
			// 	target->port_list.port_final_state[TCP_INDEX][idx].port_state);
			const char *state = port_state_to_str(
				target->port_list.port_final_state[TCP_INDEX][idx].port_state);
			size_t recap_tcp_len = strlen(recap_tcp);
			if (multi_scan)
			{
				char results_buf[256];
				build_results_str(target, args, port, results_buf,
								  sizeof(results_buf), IPPROTO_TCP);
snprintf(recap_tcp + recap_tcp_len,
         sizeof(recap_tcp) - recap_tcp_len,
         "%-*s %-*s %-*s %s\n", col_port, port_str,
         col_state, state, col_svc, svc,
         results_buf);
			}
			else
			{
snprintf(recap_tcp + recap_tcp_len,
         sizeof(recap_tcp) - recap_tcp_len,
         "%-*s %-*s %-*s", col_port, port_str,
         col_state, state, col_svc, svc);
				recap_tcp_len = strlen(recap_tcp);
				if (HAS(args->flags, F_REASON))
				{
					snprintf(recap_tcp + recap_tcp_len,
							 sizeof(recap_tcp) - recap_tcp_len, " %-*s",
							 col_reason, final_port_state.reasons[0]);
				}
				recap_tcp_len = strlen(recap_tcp);
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

static void print_target_results(t_target *target, t_args *args)
{
	t_port_state ignored_port_states[HIGHEST_PORT_STATE] = { 0 };

	printf("Nmap scan report for %s\n", target->input);
	printf("Host is up.\n");

	resolve_final_port_state(args, target);

	// We copy the entire t_port structure but update the port_state with
	// our definite state

	/* Print the port state count with their respective reason for all ignored
	state (which have more than 25 occurences accross both protocol) and erase
	them from the list */
	if (print_ignored_port_states(target, args->tcp_scan, args->udp_scan,
								  args->port_count, ignored_port_states)
		== false)
	{
		print_port_states(target, args, ignored_port_states);
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
