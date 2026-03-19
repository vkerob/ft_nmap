#include "udp.h"
#include "debug.h"
#include "protocols.h"
#include "request.h"
#include "scan.h"

#include <pthread.h>
#include <stdlib.h>

void	handle_udp_response(t_probe_queue *sent_list, u16 source_port, struct in_addr ip_src)
{

	pthread_mutex_lock(&sent_list->mut);

	t_probe *probe = get_our_probe_request(&sent_list->head, &sent_list->tail, source_port, ip_src, SCAN_UDP,
					&sent_list->nb_probe);
	pthread_mutex_unlock(&sent_list->mut);
	if (!probe)
	{
		return;
	}
	const int idx = probe->target->port_list.port_map[SCAN_UDP][source_port];
	probe->target->port_list.port_map_rev[SCAN_UDP][idx].port_state
				= OPEN;
	free(probe);
}

