#include "debug.h"
#include "protocols.h"
#include "request.h"
#include "tcp.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

void handle_tcp_response(t_probe_queue *sent_list, const u8 flags,
						 const t_scan_type scan_type, const u16 source_port,
						 const struct in_addr ip_src, const u8 ttl, t_eth_hdr *eth_hdr)
{

	pthread_mutex_lock(&sent_list->safe_mut.mutex);
	t_probe *probe
		= get_our_probe_request(&sent_list->head, &sent_list->tail, source_port,
								ip_src, scan_type, &sent_list->nb_probe);

	if (!probe)
	{
		pthread_mutex_unlock(&sent_list->safe_mut.mutex);
		return;
	}

	if (eth_hdr != NULL && probe->target->mac_address == false)
	{
		memcpy(probe->target->mac, eth_hdr->ether_shost, sizeof(u8) * ETHER_ADDR_LEN);
		probe->target->mac_address = true;
	}

	const int idx = probe->target->port_list.port_map[source_port];
	t_port	 *port = &probe->target->port_list.port_map_rev[scan_type][idx];

	/* Did the response match a state this scan can actually conclude? If not
	 * (unexpected/unsolicited packet), we must NOT resolve the port — otherwise
	 * it would stay stuck in DEFAULT. We re-queue the probe (keeping its
	 * original timestamp) so purge_timedout_probe_request classifies it later.
	 * This can happen if we scan TCP SYN 127.0.0.1 we will receive also the probe we send with
	 * only the SYN flag set, the matched boolean help us dodge this edge case */
	bool matched = false;
	switch (scan_type)
	{
	case SCAN_SYN:
		// Any RST means the port is closed (with or without ACK): nmap treats
		// a lone RST the same way, and some stacks reply RST without ACK.
		if (flags & TH_RST)
		{
			port->port_state = CLOSE;
			set_port_state_reason(port, CONNECTION_RESET);
			matched = true;
		}
		else if ((flags & TH_SYN) && (flags & TH_ACK))
		{
			port->port_state = OPEN;
			set_port_state_reason(port, SYN_ACK);
			matched = true;
		}
		break;
	case SCAN_ACK:
		if (flags & TH_RST)
		{
			port->port_state = UNFILTERED;
			set_port_state_reason(port, CONNECTION_RESET);
			matched = true;
		}
		break;
	case SCAN_FIN:
	case SCAN_NULL:
	case SCAN_XMAS:
		if (flags & TH_RST)
		{
			port->port_state = CLOSE;
			set_port_state_reason(port, CONNECTION_RESET);
			matched = true;
		}
		break;
	// SCAN UDP (nothing to do because handle in udp_response but compiler complain if not handle)
	default:
		break;
	}

	if (matched)
	{
		/* A RST carries the hop distance just as well as a SYN-ACK. */
		if (probe->target->reply_ttl == 0)
			probe->target->reply_ttl = ttl;

		atomic_fetch_sub(sent_list->outstanding, 1);
		free(probe);
	}
	else
	{
		// Unexpected response: leave the probe to the timeout path.
		add_to_probe_queue(&sent_list->head, &sent_list->tail, probe,
						   probe->timestamp);
		sent_list->nb_probe++;
	}
	pthread_mutex_unlock(&sent_list->safe_mut.mutex);
}
