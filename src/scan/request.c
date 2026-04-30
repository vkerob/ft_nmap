#include "request.h"
#include "debug.h"

#include <stdlib.h>

void erase_reference_to_node(t_probe **head, t_probe **tail, t_probe *node,
							 u16 *nb_probe)
{
	if (node->prev)
		node->prev->next = node->next;
	else
		*head = node->next;

	if (node->next)
		node->next->prev = node->prev;

	// Keep tail consistent: if we removed the tail, update it
	if (*tail == node)
		*tail = node->prev;

	node->next = NULL;
	node->prev = NULL;
	(*nb_probe)--;
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

	// print_debug_probe_request(new_request);

	return false;
}

t_probe *get_our_probe_request(t_probe **head, t_probe **tail, u16 source_port,
							   struct in_addr ip_src, t_scan_type scan_type,
							   u16 *nb_probes)
{
	t_probe *tmp = *head;

	while (tmp)
	{
		if (source_port == tmp->port && scan_type == tmp->type
			&& ip_src.s_addr == tmp->target->addr.s_addr)
			break;
		tmp = tmp->next;
	}
	if (tmp)
	{
		erase_reference_to_node(head, tail, tmp, nb_probes);
	}
	return tmp;
}
