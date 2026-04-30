#include "defines.h"
#include "scan.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

void set_port_state_reason(t_port *port, t_port_state_reason reason)
{

	char *reason_str;

	switch (reason)
	{
	case CONNECTION_RESET:
		reason_str = strdup("reset");
		break;
	case UNREACHABLE:
		reason_str = strdup("unreachable");
		break;
	case NO_RESPONSE:
		reason_str = strdup("no-response");
		break;
	default:
		return;
	}
	if (port->reasons[0] == NULL && reason_str != NULL)
	{
		port->reasons[0] = reason_str;
	}
	else if (port->reasons[1] == NULL)
	{
		port->reasons[1] = reason_str;
	}
}

static u16 get_max_port_number(u16 ports[MAX_PORT_COUNT])
{
	u16 max_port_val = 0;

	for (u16 i = 0; i < MAX_PORT_COUNT; i++)
	{
		if (ports[i] > max_port_val)
		{
			max_port_val = ports[i];
		}
	}
	return max_port_val;
}

static void delete_port_map_rev(t_port *port_map_rev[MAX_NB_SCAN_TYPE],
								u8 scan_types[MAX_NB_SCAN_TYPE], u8 index)
{
	for (u8 i = 0; i < index; i++)
	{
		free(port_map_rev[scan_types[i]]);
	}
}

// static void delete_port_map(u16 *port_map[MAX_NB_SCAN_TYPE],
// 							u8 scan_types[MAX_NB_SCAN_TYPE], u8 index)
// {
// 	for (u8 i = 0; i < index; i++)
// 	{
// 		free(port_map[scan_types[i]]);
// 	}
// }

bool link_port_list_to_each_target(t_ctx *ctx)
{
	for (u16 i = 0; i < ctx->target_count; i++)
	{
		if (init_portlist(&ctx->targets[i].port_list, ctx->args.port_count,
						  ctx->args.ports, ctx->args.scan_types,
						  ctx->args.nb_scan_types, ctx->args.tcp_scan,
						  ctx->args.udp_scan))
		{
			return true;
		}
	}
	return false;
}

static void free_port_final_state(t_port_output **final_port_state,
								  bool free_tcp_part, bool free_udp_part)
{
	if (free_tcp_part)
	{
		free(final_port_state[TCP_INDEX]);
	}
	if (free_udp_part)
	{
		free(final_port_state[UDP_INDEX]);
	}
}

bool init_portlist(t_port_list *port_list, const u16 port_count,
				   u16 ports[MAX_PORT_COUNT], u8 scan_types[MAX_NB_SCAN_TYPE],
				   const u8 nb_scan_type, const bool tcp_scan,
				   const bool udp_scan)
{
	// If not scan specified run all of them
	// if (!HAS(args->flags, F_SCAN_TYPE))

	static u16 max_port_number;

	if (!max_port_number)
	{
		max_port_number = get_max_port_number(ports);
	}

	if (tcp_scan)
	{
		// printf("port count: %d\n", port_count);
		port_list->port_final_state[TCP_INDEX]
			= calloc(port_count + 1, sizeof(t_port_output));
		if (port_list->port_final_state[TCP_INDEX] == NULL)
		{
			fprintf(stderr, "ft_nmap: calloc failed: %s\n", strerror(errno));
			return true;
		}
		for (u16 i = 0; i < port_count; i++)
		{
			port_list->port_final_state[TCP_INDEX][i].port_state = DEFAULT;
			port_list->port_final_state[TCP_INDEX][i].reasons[0] = NULL;
			port_list->port_final_state[TCP_INDEX][i].reasons[1] = NULL;
		}
		port_list->state_and_reason[TCP_INDEX] = NULL;
	}
	if (udp_scan)
	{
		port_list->port_final_state[UDP_INDEX]
			= calloc(port_count + 1, sizeof(t_port_output));
		if (port_list->port_final_state[UDP_INDEX] == NULL)
		{
			fprintf(stderr, "ft_nmap: calloc failed: %s\n", strerror(errno));
			free_port_final_state(port_list->port_final_state, true, false);
			return true;
		}
		for (u16 i = 0; i < port_count; i++)
		{
			port_list->port_final_state[UDP_INDEX][i].port_state = DEFAULT;
			port_list->port_final_state[UDP_INDEX][i].reasons[0] = NULL;
			port_list->port_final_state[UDP_INDEX][i].reasons[1] = NULL;
		}

		port_list->state_and_reason[UDP_INDEX] = NULL;
	}
	port_list->port_map = calloc(max_port_number + 1, sizeof(u16));
	if (port_list->port_map == NULL)
	{
		fprintf(stderr, "ft_nmap: calloc failed: %s\n", strerror(errno));
		free_port_final_state(port_list->port_final_state, tcp_scan, udp_scan);
		return true;
	}

	for (u16 j = 0; j < port_count; j++)
	{
		port_list->port_map[ports[j]] = j;
		if (udp_scan)
		{
			port_list->port_final_state[UDP_INDEX][j].port_number = ports[j];
		}
		if (tcp_scan)
		{
			port_list->port_final_state[TCP_INDEX][j].port_number = ports[j];
		}
	}
	for (u8 i = 0; i < nb_scan_type; i++)
	{
		const t_scan_type scan_type = scan_types[i];
		port_list->port_map_rev[scan_type]
			= calloc(port_count + 1, sizeof(t_port));
		if (port_list->port_map_rev[scan_type] == NULL)
		{
			fprintf(stderr, "ft_nmap: calloc failed: %s\n", strerror(errno));
			delete_port_map_rev(port_list->port_map_rev, scan_types, i - 1);
			free(port_list->port_map);
			free_port_final_state(port_list->port_final_state, tcp_scan,
								  udp_scan);
			return true;
		}

		for (u16 j = 0; j < port_count; j++)
		{
			port_list->port_map_rev[scan_type]->port_number = ports[j];
			port_list->port_map_rev[scan_type]->port_state = DEFAULT;
		}
	}
	return false;
}
