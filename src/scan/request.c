#include "request.h"
#include "debug.h"

#include <stdlib.h>

void erase_reference_to_node(t_probe **head, t_probe *prev, t_probe *next)
{
	if (prev)
	{
		prev->next = next;
	}
	else
	{
		// No prev means it was the head
		*head = next;
	}
	if (next)
	{
		next->prev = prev;
	}
}

bool pop_probe_request(t_probe **head, t_probe **tail, t_probe **popped_request)
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
		*tail = NULL;
		// print_debug_concise_probe(*popped_request);
	}
	// print_debug_probe_request(*popped_request);
	return true;
}

bool append_probe_request(t_probe **head, t_probe **tail, t_target *target,
						  const u16 port, const t_scan_type scan_type,
						  const u32 id)
{
	t_probe *new_request = malloc(sizeof(t_probe));
	if (!new_request)
		return true;
	new_request->target = target;
	new_request->port = port;

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

	//print_debug_probe_request(new_request);

	return false;
}
