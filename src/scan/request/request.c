#include "request.h"

#include <stdlib.h>
#include <string.h>

bool pop_probe_request(t_request **head, t_request **tail,
					   t_request **popped_request)
{
	*popped_request = *tail;

	(void)popped_request;
	if ((*tail)->prev)
	{
		*tail = (*tail)->prev;
	}
	else
	{
		*head = NULL;
	}
	return true;
}

bool append_probe_request(t_request **head, t_request **tail, t_target target,
						  u16 port, t_scan_type scan_type, u32 id)
{
	t_request *new_request = malloc(sizeof(t_request));
	if (!new_request)
		return true;
	new_request->target.ip_addr = target.addr;
	new_request->target.port = port;

	new_request->iface_info = target.iface_info;

	new_request->type = scan_type;
	new_request->id = id;
	// new_request->timestamp = 0;
	new_request->retries = 0;
	new_request->status = 0;

	new_request->next = NULL;
	new_request->prev = *tail;
	// update next of current tail or head if list is empty
	if (*tail)
		(*tail)->next = new_request;
	else
		*head = new_request;
	// update tail to new request
	*tail = new_request;

	print_debug_probe_request(new_request);

	return false;
}
