#ifndef REQUEST_H
#define REQUEST_H

#include "scan.h"
#include "typesdef.h"

#include <arpa/inet.h>

typedef struct s_target_probe
{
	struct in_addr ip_addr;
	u16			   port;
} t_target_probe;

typedef struct s_request
{
	t_target_probe	  target;
	t_iface_info	  iface_info;
	enum e_scan_type  type;
	time_t			  timestamp;
	u32				  id;
	u8				  retries;
	u8				  status;
	struct s_request *prev;
	struct s_request *next;
} t_request;

// typedef struct s_probe_request_sent
// {
// 	time_t						 timestamp;
// 	u8							 retries;
// 	struct s_probe_request		*request;
// 	struct s_probe_request_sent *next;
// 	struct s_probe_request_sent *prev;
// } t_probe_request_sent;

void print_debug_probe_request(t_request *request);

bool pop_probe_request(t_request **head, t_request **tail,
				 t_request **popped_request);

bool append_probe_request(t_request **head, t_request **tail, t_target target,
						  u16 port, t_scan_type scan_type, u32 id);

bool update_pending_probe_request_list(t_request **head_pending_list,
									   t_request **tail_pending_list,
									   t_request  *request,
									   time_t	   sent_timestamp);

#endif
