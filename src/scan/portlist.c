#include "defines.h"
#include "scan.h"
#include "utils.h"

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
	case SYN_ACK:
		reason_str = strdup("syn-ack");
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

static void delete_port_map_rev(t_port *port_map_rev[MAX_NB_SCAN_TYPE],
								u8 scan_types[MAX_NB_SCAN_TYPE], u8 index)
{
	for (u8 i = 0; i < index; i++)
	{
		free(port_map_rev[scan_types[i]]);
	}
}


bool init_port_lists(t_ctx *ctx)
{
	for (u16 i = 0; i < ctx->target_count; i++)
	{
		if (init_portlist(&ctx->targets[i].port_list, ctx->args.port_count,
						  ctx->args.ports, ctx->args.scan_types,
						  ctx->args.nb_scan_types, ctx->args.tcp_scan,
						  ctx->args.udp_scan, &ctx->args.max_port_nb))
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
				   const bool udp_scan, u16 *max_port_nb)
{
	*max_port_nb = get_max_port_number(ports);

	if (tcp_scan)
	{
		port_list->port_final_state[TCP_INDEX]
			= calloc(port_count + 1, sizeof(t_port_output));
		if (port_list->port_final_state[TCP_INDEX] == NULL)
		{
			LOG("ft_nmap: calloc failed: %s\n", strerror(errno));
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
			LOG("ft_nmap: calloc failed: %s\n", strerror(errno));
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
	/* port_map is indexed by raw destination port number, so we need
	 * (max_port_nb + 1) entries (port 0 unused, ports 1..max_port_nb usable).
	 * The subject allows scanning ports < 1024 (default range is 1-1024). */
	const size_t port_map_count = (size_t)(*max_port_nb) + 1;
	port_list->port_map = calloc(port_map_count, sizeof(int));
	if (port_list->port_map == NULL)
	{
		LOG("ft_nmap: malloc failed: %s\n", strerror(errno));
		free_port_final_state(port_list->port_final_state, tcp_scan, udp_scan);
		return true;
	}
	memset(port_list->port_map, -1, port_map_count * sizeof(int));

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
			LOG("ft_nmap: calloc failed: %s\n", strerror(errno));
			delete_port_map_rev(port_list->port_map_rev, scan_types, i);
			free(port_list->port_map);
			free_port_final_state(port_list->port_final_state, tcp_scan,
								  udp_scan);
			return true;
		}

		for (u16 j = 0; j < port_count; j++)
		{
			port_list->port_map_rev[scan_type][j].port_number = ports[j];
			port_list->port_map_rev[scan_type][j].port_state = DEFAULT;
		}
	}
	return false;
}
