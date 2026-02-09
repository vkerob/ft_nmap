#ifndef PROBE_REQUEST_H
#define PROBE_REQUEST_H

#include "defines.h"
#include "typesdef.h"
#include "scan.h"

#include <arpa/inet.h>

typedef struct	s_target_probe
{
	char	ip[INET_ADDRSTRLEN];
	u16		port;
}	t_target_probe;

typedef struct	s_probe_request
{
	t_target_probe					target;
	enum e_scan_type				type;
	u32											id;
	time_t									timestamp;
	u8											retries;
	u8											status;
	struct s_probe_request	*next;
	struct s_probe_request	*prev;
}	t_probe_request;

void	print_debug_probe_request(t_probe_request *request);

bool	pop_probe_request(t_probe_request **head, t_probe_request *tail, t_probe_request **popped_request);

bool	initial_probe_requests(
							t_target *targets,
							size_t target_count,
							u16 *ports,
							u16 port_count,
							u8 scan_types[MAX_NB_SCAN_TYPE],
							u8 nb_scan_types,
							t_probe_request **head,
							t_probe_request **tail);

#endif
