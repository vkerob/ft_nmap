#include "debug.h"
#include "icmp.h"
#include "protocols.h"
#include "request.h"
#include "scan.h"
#include "tcp.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

/* Map every ICMP type-3 (destination unreachable) code to its nmap-style
 * reason. Any code not listed here still indicates filtering (we just fall
 * back to a generic UNREACHABLE reason for it). */
static t_port_state_reason icmp_code_to_reason(const u8 code)
{
	switch (code)
	{
	case 0:
		return NET_UNREACH;
	case 1:
		return HOST_UNREACH;
	case 2:
		return PROTO_UNREACH;
	case 3:
		return PORT_UNREACH;
	case 4:
		return FRAG_NEEDED;
	case 5:
		return SRC_ROUTE_FAILED;
	case 6:
		return NET_UNKNOWN;
	case 7:
		return HOST_UNKNOWN;
	case 8:
		return HOST_ISOLATED;
	case 9:
		return NET_PROHIB;
	case 10:
		return HOST_PROHIB;
	case 11:
		return NET_UNREACH_TOS;
	case 12:
		return HOST_UNREACH_TOS;
	case 13:
		return ADMIN_PROHIB;
	default:
		return UNREACHABLE;
	}
}

/* Can either be from a UDP or TCP probe so we pass the scan type as argument */
void handle_icmp_response(t_probe_queue *sent_list, const u16 source_port,
						  const struct in_addr ip_src, t_icmp_hdr icmp_hdr,
						  const t_scan_type scan_type, const u8 protocol,
						  t_eth_hdr *eth_hdr)
{
	if (ICMP_TYPE(icmp_hdr) != 3)
	{
		return;
	}

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
		memcpy(probe->target->mac, eth_hdr->ether_shost,
			   sizeof(u8) * ETHER_ADDR_LEN);
		probe->target->mac_address = true;
	}
	const int idx = probe->target->port_list.port_map[source_port];
	t_port	 *port = &probe->target->port_list.port_map_rev[scan_type][idx];
	const u8  code = ICMP_CODE(icmp_hdr);

	/* Port-unreachable on a UDP probe is the only unreachable code that
	 * proves the port itself is closed; every other ICMP type-3 message
	 * only proves something along the path is filtering the probe. */
	if (code == 3 && protocol == IPPROTO_UDP)
		port->port_state = CLOSE;
	else
		port->port_state = FILTERED;
	set_port_state_reason(port, icmp_code_to_reason(code));
	atomic_fetch_sub(sent_list->outstanding, 1);
	pthread_mutex_unlock(&sent_list->safe_mut.mutex);
	free(probe);
}
