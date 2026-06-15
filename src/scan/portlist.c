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
		reason_str = "reset";
		break;
	case UNREACHABLE:
		reason_str = "unreachable";
		break;
	case NO_RESPONSE:
		reason_str = "no-response";
		break;
	case SYN_ACK:
		reason_str = "syn-ack";
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

bool init_port_lists(t_ctx *ctx)
{
	for (u16 i = 0; i < ctx->target_count; i++)
	{
		if (init_portlist(&ctx->targets[i].port_list, ctx->args.port_count,
						  ctx->args.ports, ctx->args.scan_types,
						  ctx->args.nb_scan_types, ctx->args.tcp_scan,
						  ctx->args.udp_scan, &ctx->args.max_port_nb,
						  ctx->args.port_map))
		{
			return true;
		}
	}
	return false;
}

bool init_portlist(t_port_list *port_list, const u16 port_count,
				   u16 ports[MAX_PORT_COUNT], u8 scan_types[MAX_NB_SCAN_TYPE],
				   const u8 nb_scan_type, const bool tcp_scan,
				   const bool udp_scan, u16 *max_port_nb, int *port_map)
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

	port_list->port_map = port_map;

	for (u16 j = 0; j < port_count; j++)
	{
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
