#include "defines.h"
#include "scan.h"

#include <stdlib.h>
#include <string.h>

static u16	get_max_port_number(u16 ports[MAX_PORT_COUNT])
{
	u16	max_port_val = 0;

	for (u16 i = 0; i < MAX_PORT_COUNT; i++)
	{
		if (ports[i] > max_port_val){
			max_port_val = ports[i];
		}
	}
	return max_port_val;
}

static	void delete_port_map_rev(t_port *port_map_rev[MAX_NB_SCAN_TYPE], u8 scan_types[MAX_NB_SCAN_TYPE], u8 index)
{
	for (u8 i = 0; i < index; i++)
	{
		free(port_map_rev[scan_types[i]]);
	}
}

static	void delete_port_map(u16 *port_map[MAX_NB_SCAN_TYPE], u8 scan_types[MAX_NB_SCAN_TYPE], u8 index)
{
	for (u8 i = 0; i < index; i++)
	{
		free(port_map[scan_types[i]]);
	}
}

bool	init_portlist(
	t_port_list *port_list,
	u16 port_count,
	u16 ports[MAX_PORT_COUNT],
	u8 nb_scan_types,
	u8 scan_types[MAX_NB_SCAN_TYPE])
{
	// If not scan specified run all of them
	// if (!HAS(args->flags, F_SCAN_TYPE))

	for (u8 i = 0; i < nb_scan_types; i++)
	{
		u8 idx = scan_types[i];
		port_list->port_map_rev[idx] = calloc(port_count, sizeof(t_port));
		if (port_list->port_map_rev[idx] == NULL)
		{
			delete_port_map_rev(port_list->port_map_rev, scan_types, i - 1);
			return false;
		}
		port_list->port_map[idx] = calloc(get_max_port_number(ports), sizeof(u16));
		if (port_list->port_map[idx] == NULL)
		{
			delete_port_map(port_list->port_map, scan_types, i - 1);
			return false;
		}


		for (u16 j = 0; j < port_count; j++)
		{
			port_list->port_map[i][ports[j]] = j;
		}

		// memcpy(
		// 	port_list[->port_map_rev, ports, port_count * sizeof(u16)
		// );
	}
	return true;
}
