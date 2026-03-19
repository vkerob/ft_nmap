#include "debug.h"
#include "protocols.h"
#include "request.h"
#include "tcp.h"

#include <pthread.h>
#include <stdlib.h>

void handle_tcp_response(t_probe_queue *sent_list, u8 flags,
						 t_scan_type scan_type, u16 source_port,
						 struct in_addr ip_src)
{

	pthread_mutex_lock(&sent_list->mut);
	t_probe *probe
		= get_our_probe_request(&sent_list->head, &sent_list->tail, source_port, ip_src, scan_type,
					&sent_list->nb_probe);
	pthread_mutex_unlock(&sent_list->mut);

	if (!probe)
	{
		return;
	}
	const int idx = probe->target->port_list.port_map[scan_type][source_port];
	switch (scan_type)
	{
	case SCAN_SYN:
		if (flags & (TH_RST | TH_ACK))
		{

			probe->target->port_list.port_map_rev[scan_type][idx].port_state
				= CLOSE;
		}
		else if (flags & (TH_SYN | TH_ACK))
		{
			probe->target->port_list.port_map_rev[scan_type][idx].port_state
				= OPEN;
		}
		break;
	case SCAN_ACK:
		if (flags & (TH_RST | TH_ACK))
		{
			probe->target->port_list.port_map_rev[scan_type][idx].port_state
				= UNFILTERED;
		}
		else
		{
			probe->target->port_list.port_map_rev[scan_type][idx].port_state
				= UNKNOWN;
		}
		break;
	case SCAN_FIN:
	case SCAN_NULL:
	case SCAN_XMAS:
		if (flags & (TH_RST | TH_ACK))
		{
			probe->target->port_list.port_map_rev[scan_type][idx].port_state
				= CLOSE;
		}
		else
		{
			probe->target->port_list.port_map_rev[scan_type][idx].port_state
				= UNKNOWN;
		}
		break;
	default:
		break;
	}
	free(probe);
}
