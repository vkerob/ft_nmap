#include "defines.h"
#include "scan.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

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
						  ctx->args.nb_scan_types))
		{
			return true;
		}
	}
	return false;
}

bool init_portlist(t_port_list *port_list, const u16 port_count,
				   u16 ports[MAX_PORT_COUNT], u8 scan_types[MAX_NB_SCAN_TYPE],
				   const u8 nb_scan_type)
{
	// If not scan specified run all of them
	// if (!HAS(args->flags, F_SCAN_TYPE))

	static u16 max_port_number;

	if (!max_port_number)
	{
		max_port_number = get_max_port_number(ports);
	}
	port_list->port_final_state = calloc(port_count + 1, sizeof(t_port_state));
	if (port_list->port_final_state == NULL) {
		fprintf(stderr, "ft_nmap: calloc failed: %s\n", strerror(errno));
		return true;
	}
	port_list->port_map = calloc(max_port_number + 1, sizeof(u16));
	if (port_list->port_map == NULL)
	{
		fprintf(stderr, "ft_nmap: calloc failed: %s\n", strerror(errno));
		free(port_list->port_final_state);
		return true;
	}

	for (u16 j = 0; j < port_count; j++)
	{
		port_list->port_map[ports[j]] = j;
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
			free(port_list->port_final_state);
			return true;
		}

		for (u16 j = 0; j < port_count; j++)
		{
			port_list->port_map_rev[scan_type]->port_number = ports[j];
			port_list->port_map_rev[scan_type]->port_state = UNKNOWN;
		}
	}
	return false;
}
