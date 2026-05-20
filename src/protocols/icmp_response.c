#include "debug.h"
#include "icmp.h"
#include "protocols.h"
#include "request.h"
#include "scan.h"
#include "tcp.h"

#include <pthread.h>
#include <stdlib.h>
#define ICMP_ERROR_HIGHEST_IDX 6

/* Can either be from a UDP or TCP probe so we pass the scan type as argument */
void handle_icmp_response(t_probe_queue *sent_list, const u16 source_port,
						  const struct in_addr ip_src, t_icmp_hdr icmp_hdr,
						  const t_scan_type scan_type, const u8 protocol)
{
	(void)protocol;
	// ICMP unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)
	static u8 icmp_error_codes[6] = { 1, 2, 3, 9, 10, 13 };
	if (ICMP_TYPE(icmp_hdr) != 3)
	{
		return;
	}

	pthread_mutex_lock(&sent_list->mut);
	t_probe *probe
		= get_our_probe_request(&sent_list->head, &sent_list->tail, source_port,
								ip_src, scan_type, &sent_list->nb_probe);
	if (!probe)
	{
		pthread_mutex_unlock(&sent_list->mut);
		sync_printf("Probe not found\n");
		return;
	}
	const int idx = probe->target->port_list.port_map[PORT(source_port)];
	t_port	 *port = &probe->target->port_list.port_map_rev[scan_type][idx];
	for (u8 i = 0; i < ICMP_ERROR_HIGHEST_IDX; i++)
	{

		if (ICMP_CODE(icmp_hdr) == icmp_error_codes[i])
		{
			if (icmp_error_codes[i] == 3 && protocol == IPPROTO_UDP)
			{
				port->port_state = CLOSE;
			}
			else
			{
				port->port_state = FILTERED;
			}
			set_port_state_reason(port, UNREACHABLE);
			pthread_mutex_unlock(&sent_list->mut);
			free(probe);
			return;
		}
	}
	port->port_state = UNKNOWN;
	pthread_mutex_unlock(&sent_list->mut);
	free(probe);
}
