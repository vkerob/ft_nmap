#ifndef REQUEST_H
#define REQUEST_H

#include "scan.h"
#include "typesdef.h"

#include <arpa/inet.h>

typedef struct s_probe
{
	t_target		*target;
	u16				 port;
	enum e_scan_type type;
	struct timeval	 timestamp;
	u32				 id;
	u8				 retries;
	u8				 status;
	struct s_probe	*prev;
	struct s_probe	*next;
} t_probe;

void print_debug_probe_request(t_probe *request);

bool pop_probe_request(t_probe **head, t_probe **tail,
					   t_probe **popped_request);

bool append_probe_request(t_probe **head, t_probe **tail, t_target *target,
						  u16 port, t_scan_type scan_type, u32 id);

bool update_sent_queue(t_probe **head_sent_list, t_probe **tail_sent_list,
					   t_probe *request, struct timeval sent_timestamp);

void erase_reference_to_node(t_probe **head, t_probe *prev, t_probe *next);
#endif
