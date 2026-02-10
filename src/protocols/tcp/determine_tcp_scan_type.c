#include "typesdef.h"
#include "scan.h"

#include <stdlib.h>

static t_port_range_scan_type	g_port_range_tcp[MAX_SCAN_TYPE_TCP] =
{
	{
		.scan_type = SCAN_SYN,
		.min_port_range = MIN_SRC_PORT_NUMBER,
		.max_port_range = 14335,
	},
	{
		.scan_type = SCAN_NULL,
		.min_port_range = 14336,
		.max_port_range = 27647
	},
	{
		.scan_type = SCAN_ACK,
		.min_port_range = 27648,
		.max_port_range = 40959
	},
	{
		.scan_type = SCAN_FIN,
		.min_port_range = 40960,
		.max_port_range = 54271
	},
	{
		.scan_type = SCAN_XMAS,
		.min_port_range = 54272,
		.max_port_range = MAX_PORT_NUMBER
	}
};

u16	get_random_source_port_in_scantype_interval(t_scan_type scan_type)
{
	t_port_range_scan_type port_range = g_port_range_tcp[scan_type];

	return rand() % (port_range.max_port_range - port_range.min_port_range);
}

t_scan_type	determine_tcp_scan_type(u16 source_port)
{
	for (u8 i = MAX_SCAN_TYPE_TCP - 1; i >= 0; i--)
	{
		if (source_port >= g_port_range_tcp[i].min_port_range)
		{
			return g_port_range_tcp[i].scan_type;
		}
	}
	return SCAN_UNKNOWN;
}
