#ifndef SHARED_H
#define SHARED_H

#include "defines.h"
#include "typesdef.h"
#include "probe_request.h"
#include "parsing.h"
#include "scan.h"

#include <pcap/pcap.h>

typedef struct	s_shared_data
{
	pcap_t								*handle;
	pthread_mutex_t				mutex;
	u8										gateway_mac[ETH_ALEN]; // for ethernet header (bonus // spoofing)
	char									source_ip[INET_ADDRSTRLEN];
	_Atomic u16						id;
	_Atomic u16						base_seq;
	// _Atomic u16				base_port;
	_Atomic u32						nb_probe_requests;
	t_probe_request				*request_list_head;
	t_probe_request				*request_list_tail;
	t_target							*targets;
	size_t								target_count;
	u16										port_count;
	// one for each interface
	t_probe_request_sent	**pending_request_head;
	t_probe_request_sent	**pending_request_tail;
	pthread_mutex_t				*pending_request_list_mut;
}	t_shared_data;

void initialize_shared_data(
							t_shared_data *shared_data,
							pcap_t *handle,
							t_ctx *ctx);
#endif