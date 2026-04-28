#include "scan.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define PRINT_LIMIT 25

// ── Helpers
// ───────────────────────────────────────────────────────────────────

static char *port_state_to_str(t_port_state state)
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

// static const char *port_state_color(t_port_state state)
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

// static const char *get_service_name(u16 port)
// {
// 	const struct servent *svc = getservbyport(htons(port), "tcp");
// 	if (svc)
// 		return svc->s_name;
// 	svc = getservbyport(htons(port), "udp");
// 	if (svc)
// 		return svc->s_name;
// 	return "unknown";
// }

static void update_port_reasons(t_port_output *port_conclusion,
								const t_port  *port)
{
	//  Same port state but maybe the reason the port is in that state is
	//  different
	if (port_conclusion->port_state == port->port_state)
	{
		if (strcmp(port_conclusion->reasons[0], port->reasons[0]) != 0)
		{
			strcpy(port_conclusion->reasons[0], port->reasons[0]);
		}

		else if (strcmp(port_conclusion->reasons[1], port->reasons[1]) != 0)
		{
			strcpy(port_conclusion->reasons[1], port->reasons[1]);
		}
	}
	else
	{
		// Different state so we get the new reason
		if (port->reasons[0])
		{
			port_conclusion->reasons[0] = port->reasons[0];
		}
		if (port->reasons[1])
		{
			port_conclusion->reasons[1] = port->reasons[1];
		}
		else
		{
			port_conclusion->reasons[1] = NULL;
		}
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
		if (port_conclusion->port_state != OPEN
			&& port_conclusion->port_state != FILTERED)
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
		if (port_conclusion->port_state != OPEN
			&& port_conclusion->port_state != CLOSE)
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
			|| port_conclusion->port_state == CLOSE
			|| port_conclusion->port_state == UNFILTERED)
		{
			set_unknown_port_state(port_conclusion);
		}
		else if (port_conclusion->port_state == OPEN_FILTERED)
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

// Return the next most common ignored state (which the most port shared a
// state) or unknown if none are left
bool get_next_ignored_state(t_port_state_and_reason **head,
							t_port_state_and_reason	 *next_ignored_state,
							int						 *nb_port_per_state)
{

	(void)nb_port_per_state;
	static t_port_state_and_reason prev_ignored_state
		= { .port_state = UNKNOWN, .reason = NULL };

	// TODO: replace by u16
	// int max = PRINT_LIMIT;
	int i = 0;

	t_port_state_and_reason *tmp = *head;
	t_port_state_and_reason *prev = NULL;

	int max = PRINT_LIMIT;

	int index_next_ignored_port_state = -1;
	// If a port state got multiple reasons
	while (tmp)
	{
		if (tmp->port_state == prev_ignored_state.port_state)
		{
			memcpy(next_ignored_state, tmp, sizeof(t_port_state_and_reason));
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
		if (tmp->count > max)
		{
			max = tmp->count;
			index_next_ignored_port_state = i;
		}
		prev = tmp;
		tmp = tmp->next;
		i++;
	}

	// If we get there we returned every reason for an ignored port state so we
	// get the next ignored by taking the port state which got the most port in
	// his state
	tmp = *head;
	prev = NULL;
	i = 0;
	while (tmp)
	{
		if (i == index_next_ignored_port_state)
		{
			memcpy(next_ignored_state, tmp, sizeof(t_port_state_and_reason));
			memcpy(&prev_ignored_state, tmp, sizeof(t_port_state_and_reason));
			// erase
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
		tmp = tmp->next;
	}

	return false;
}

/* This is for a special case when some port can be filtered because we got a
IMCP error unreachable code, and other can be filtered because we didn't get any
response. In this  case we separate the 'not shown' output between those two
reasons */
// static void get_common_reason(t_port_output *port_final_state, u16
// port_count, char *next_common_reason, int *common_reason_count)
// {
// 	int count_reason1 = 0;
// 	int count_reason2 = 0;
// 	char reason1[16] = {0};
// 	char reason2[16] = {0};

// 	for (u16 i = 0; i < port_count; i++)
// 	{
// 		if (reason1[0] == '\0'){
// 			strcpy(reason1, port_final_state[i].reasons[0]);
// 			count_reason1++;
// 		}
// 		else if (reason2[0] == '\0' && port_final_state[){
// 			strcpy(reason2, port_final_state[i].reasons[1]);
// 			count_reason2++;
// 		}
// 		else{
// 			if (strcmp(reason1, port_final_state[i].reason)){
// 				count_reason1++;
// 			}
// 			else if (strcmp(reason2, port_final_state[i].reason)){
// 				count_reason2++;
// 			}
// 		}
// 	}

// 	if (count_reason1 > count_reason2){
// 		strcpy(next_common_reason, reason1);
// 		*common_reason_count = count_reason1;
// 	}
// 	else{
// 		strcpy(next_common_reason, reason2);
// 		*common_reason_count = count_reason2;
// 	}
// }

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

// Builds the "Not shown:" summary line for all states except OPEN which have a
// number ports over PRINT_LIMIT in which case they are considered "ignored".
// They are print from the most common to the least common and with a reason
// associated (no-response, reset, ...)
// static void build_not_shown_str(int   *state_count,
// 								t_port_output **port_final_state,
// 								u16 port_count, bool tcp_scan, bool udp_scan)
// {
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

// static void build_results_str(const t_target *target, const t_args *args,
// 							  const u16 port, char *buf, size_t buf_size)
// {
// 	char   scan_name[16];
// 	size_t offset = 0;

// 	for (u8 i = 0; i < args->nb_scan_types; i++)
// 	{
// 		const t_scan_type  stype = args->scan_types[i];
// 		const u16		   idx = target->port_list.port_map[port];
// 		const t_port_state state
// 			= target->port_list.port_map_rev[stype][idx].port_state;

// 		scan_type_to_str(stype, scan_name);

// 		const int written = snprintf(buf + offset, buf_size - offset, "%s(%s) ",
// 									 scan_name, port_state_to_str(state));
// 		if (written < 0 || (size_t)written >= buf_size - offset)
// 			break;
// 		offset += (size_t)written;
// 	}
// 	if (offset > 0 && buf[offset - 1] == ' ')
// 		buf[offset - 1] = '\0';
// }

// Compute max "port/proto" string width across all ports of a target
// so that columns align regardless of port numbers (like nmap does).
// static int compute_port_col_width(t_args *args)
// {
// 	int max = 9; // minimum: "65535/tcp"
// 	for (u16 i = 0; i < args->port_count; i++)
// 	{
// 		const int w = snprintf(NULL, 0, "%u/tcp", args->ports[i]);
// 		if (w > max)
// 			max = w;
// 	}
// 	return max + 2; // extra padding like nmap
// }

void find_or_update_state_and_reason_combination(
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
		return;
	}
	while (tmp)
	{
		// printf("%s / %s\n", tmp->reason, reason);
		// printf("%s / %s\n", port_state_to_str(port_state),
		// 	   port_state_to_str(tmp->port_state));
		// printf("%d\n", strcmp(tmp->reason, reason));
		if (strcmp(tmp->reason, reason) == 0 && port_state == tmp->port_state)
		{
			tmp->count++;
			return;
		}
		prev = tmp;
		tmp = tmp->next;
	}
	printf("HUH\n");
	prev->next = calloc(1, sizeof(t_port_state_and_reason));
	prev->next->reason = reason;
	prev->next->count = 1;
	prev->next->port_state = port_state;
}

static void print_target_results(t_target *target, t_args *args)
{
	char ip_str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &target->addr, ip_str, sizeof(ip_str));

	printf("Nmap scan report for %s\n", ip_str);
	printf("Host is up.\n");

	for (u16 i = 0; i < args->port_count; i++)
	{
		for (u8 j = 0; j < args->nb_scan_types; j++)
		{
			const t_scan_type scan_type_index = args->scan_types[j];
			const u8		  protocol_index
				= (scan_type_index == SCAN_UDP) ? UDP_INDEX : TCP_INDEX;

			update_definitive_port_state_and_reason(
				&target->port_list.port_final_state[protocol_index][i],
				&target->port_list.port_map_rev[scan_type_index][i]);
			if (target->port_list.port_final_state[protocol_index][i].port_state
				== UNKNOWN)
				break;
		}
		if (args->tcp_scan)
		{
			t_port_output target_port_output
				= target->port_list.port_final_state[TCP_INDEX][i];
			t_port_state target_port_state = target_port_output.port_state;
			find_or_update_state_and_reason_combination(
				&target->port_list.state_and_reason[TCP_INDEX],
				target_port_state, target_port_output.reasons[0]);

			// Second reason can be empty
			if (target->port_list.port_final_state[TCP_INDEX][i].reasons[1]
				!= NULL)
			{
				find_or_update_state_and_reason_combination(
					&target->port_list.state_and_reason[TCP_INDEX],
					target_port_state, target_port_output.reasons[1]);
			}
			// The port count in each state is global between udp and tcp
			target->port_list.state_count[target_port_state]++;
		}

		if (args->udp_scan)
		{
			// Since there's only one UDP scan available the port can only be in
			// a state for a single reason
			t_port_output target_port_output
				= target->port_list.port_final_state[UDP_INDEX][i];
			t_port_state target_port_state = target_port_output.port_state;
			find_or_update_state_and_reason_combination(
				&target->port_list.state_and_reason[UDP_INDEX],
				target_port_state, target_port_output.reasons[0]);
			target->port_list.state_count[target_port_state]++;
		}

		// We copy the entire t_port structure but update the port_state with
		// our definite state
		// memcpy(target->port_list.port_final_state[idx],
		// target->port_list.port_map_rev[idx]);
		// target->port_list.port_final_state[idx]->port_state = port_state;
	}

	t_port_state_and_reason next_ignored_state
		= { .port_state = DEFAULT, .reason = NULL };
	if (args->tcp_scan)
	{
		while (get_next_ignored_state(
			&target->port_list.state_and_reason[TCP_INDEX], &next_ignored_state,
			target->port_list.state_count))
		{
			printf("%d in %s state (%s)\n", next_ignored_state.count,
				   port_state_to_str(next_ignored_state.port_state),
				   next_ignored_state.reason);
		}
	}
	// t_port_state_and_reason *tmp
	// 	= target->port_list.state_and_reason[TCP_INDEX];
	// while (tmp)
	// {
	// 	printf("%d in %s state (%s)\n", tmp->count,
	// 		   port_state_to_str(tmp->port_state), tmp->reason);
	// 	tmp = tmp->next;
	// }
	// char *s = port_state_to_str(
	//	target->port_list.port_final_state[TCP_INDEX][0].port_state);
	// printf("%s (%s) (%s)\n", s,
	//	   target->port_list.port_final_state[TCP_INDEX][0].reasons[0]);
	//  for (u8 i = 0; i < HIGHEST_PORT_STATE; i++)
	//  {
	//  	printf("%s: %d\n", port_state_to_str(i),
	//  		   target->port_list.state_count[i]);
	//  }
	// t_port_state_and_reason *tmp
	//	= target->port_list.state_and_reason[TCP_INDEX];

	// while (tmp)
	//{

	//	printf("%s: %d (%s)\n", port_state_to_str(tmp->port_state), tmp->count,
	//		   tmp->reason);
	//	tmp = tmp->next;
	//}
	// t_port_state port_state
	//	= get_next_ignored_state(target->port_list.state_count);
	// bool not_shown = false;
	// while (port_state != UNKNOWN)
	//{
	//	if (not_shown == false)
	//	{
	//		printf("Not shown: ");
	//		not_shown = true;
	//	}
	// }

	// build_not_shown_str(target->port_list.state_count,
	//					target->port_list.port_final_state, args->port_count,
	//					args->tcp_scan, args->udp_scan);

	// If we got no port's open and all port state occurrences exceed 25
	// if (nb_open == 0)
	//{
	//	printf("All %u scanned ports on %s are in ignored states.\n",
	//			   args->port_count, ip_str);
	//	build_not_shown_str(nb_closed, nb_filtered, nb_open_filtered);
	//}

	//	const int  col_port = compute_port_col_width(args);
	//	const int  col_state = 14;
	//	const int  col_svc = 12;
	//	const bool multi_scan = args->nb_scan_types > 1;
	//
	//	if (multi_scan)
	//		printf("%-*s %-*s %-*s %s\n", col_port, "PORT", col_state, "STATE",
	//			   col_svc, "SERVICE", "SCAN RESULTS");
	//	else
	//		printf("%-*s %-*s %s\n", col_port, "PORT", col_state, "STATE",
	//			   "SERVICE");
	//
	//	for (u16 i = 0; i < args->port_count; i++)
	//	{
	//		const u16 port = args->ports[i];
	//		const u16 idx = target->port_list.port_map[args->ports[i]];
	//
	//		t_port_output conclusion[MAX_PROTO_COUNT] = { 0 };
	//
	//		if (args->tcp_scan)
	//		{
	//			memcpy(&conclusion[TCP_INDEX],
	//				   &target->port_list.port_final_state[TCP_INDEX][idx],
	//				   sizeof(t_port_output));
	//		}
	//		if (args->udp_scan)
	//		{
	//			memcpy(&conclusion[UDP_INDEX],
	//				   &target->port_list.port_final_state[UDP_INDEX][idx],
	//				   sizeof(t_port_output));
	//		}
	//
	//		if (conclusion[0].port_state != OPEN
	//			&& target->port_list.state_count[conclusion[0].port_state]
	//				   > PRINT_LIMIT)
	//		{
	//			continue;
	//		}
	//
	//		char port_str[16];
	//		if (args->udp_scan)
	//			snprintf(port_str, sizeof(port_str), "%u/udp", port);
	//		else if (args->tcp_scan)
	//			snprintf(port_str, sizeof(port_str), "%u/tcp", port);
	//
	//		const char *svc = get_service_name(port);
	//		const char *color = port_state_color(conclusion->port_state);
	//		const char *state = port_state_to_str(conclusion->port_state);
	//
	//		if (multi_scan)
	//		{
	//			char results_buf[256];
	//			build_results_str(target, args, port, results_buf,
	//							  sizeof(results_buf));
	//			printf("%-*s %s%-*s%s %-*s %s\n", col_port, port_str, color,
	//				   col_state, state, ANSI_COLOR_RESET, col_svc, svc,
	//				   results_buf);
	//		}
	//		else
	//		{
	//			printf("%-*s %s%-*s%s %s\n", col_port, port_str, color,
	// col_state, 				   state, ANSI_COLOR_RESET, svc);
	//		}
	//	}
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
