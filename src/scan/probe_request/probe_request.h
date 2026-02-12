#ifndef PROBE_REQUEST_H
#define PROBE_REQUEST_H

#include "scan.h"
#include "typesdef.h"

#include <arpa/inet.h>

typedef struct s_target_probe
{
	char ip[INET_ADDRSTRLEN];
	u16	 port;
} t_target_probe;

typedef struct s_probe_request
{
	t_target_probe			target;
	t_iface_info			iface_info;
	enum e_scan_type		type;
	time_t					timestamp;
	u32						id;
	u8						retries;
	u8						status;
	struct s_probe_request *next;
	struct s_probe_request *prev;
} t_probe_request;

// typedef struct s_probe_request_sent
// {
// 	time_t						 timestamp;
// 	u8							 retries;
// 	struct s_probe_request		*request;
// 	struct s_probe_request_sent *next;
// 	struct s_probe_request_sent *prev;
// } t_probe_request_sent;

void print_debug_probe_request(t_probe_request *request);

bool pop_probe_request(t_probe_request **head, t_probe_request **tail,
					   t_probe_request **popped_request);

bool initial_probe_requests(t_ctx *ctx, t_probe_request **head,
							t_probe_request **tail);

bool update_pending_probe_request_list(t_probe_request **head_pending_list,
									   t_probe_request **tail_pending_list,
									   t_probe_request	*request,
									   time_t			 sent_timestamp);

#endif
