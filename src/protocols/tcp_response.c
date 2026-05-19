#include "debug.h"
#include "protocols.h"
#include "request.h"
#include "tcp.h"

#include <pthread.h>
#include <stdlib.h>

void handle_tcp_response(t_probe_queue *sent_list, const u8 flags,
						 const t_scan_type scan_type, const u16 source_port,
						 const struct in_addr ip_src)
{

	pthread_mutex_lock(&sent_list->mut);
	t_probe *probe
		= get_our_probe_request(&sent_list->head, &sent_list->tail, source_port,
								ip_src, scan_type, &sent_list->nb_probe);
	pthread_mutex_unlock(&sent_list->mut);

	if (!probe)
	{
		return;
	}
	const int idx = probe->target->port_list.port_map[source_port];
	t_port	 *port = &probe->target->port_list.port_map_rev[scan_type][idx];
	switch (scan_type)
	{
	case SCAN_SYN:
		if ((flags & TH_RST) && (flags & TH_ACK))
		{
			port->port_state = CLOSE;
			set_port_state_reason(port, CONNECTION_RESET);
		}
		else if ((flags & TH_SYN) && (flags & TH_ACK))
		{
			port->port_state = OPEN;
			set_port_state_reason(port, SYN_ACK);
		}
		break;
	case SCAN_ACK:
		if (flags & TH_RST)
		{
			port->port_state = UNFILTERED;
			set_port_state_reason(port, CONNECTION_RESET);
		}
		else
		{
			port->port_state = UNKNOWN;
		}
		break;
	case SCAN_FIN:
	case SCAN_NULL:
	case SCAN_XMAS:
		if (flags & TH_RST)
		{
			port->port_state = CLOSE;
			set_port_state_reason(port, CONNECTION_RESET);
		}
		else
		{
			port->port_state = UNKNOWN;
		}
		break;
	// SCAN UDP (nothing to do but compiler complain if not handle)
	default:
		break;
	}
	free(probe);
}
