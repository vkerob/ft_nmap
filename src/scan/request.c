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

void pop_probe_request(t_probe **head, t_probe **tail, t_probe **popped_request)
{
	t_probe *node = *tail;

	*popped_request = node;

	if (node->prev)
	{
		*tail = node->prev;
		(*tail)->next = NULL;
	}
	else
	{
		*head = NULL;
		*tail = NULL;
	}
	/* Fully detach the popped node so no dangling links remain. */
	node->prev = NULL;
	node->next = NULL;
}

int append_probe_request(t_probe **head, t_probe **tail, t_target *target,
						 const u16 port, const t_scan_type scan_type,
						 const u32 id)
{
	t_probe *new_request = malloc(sizeof(t_probe));
	if (!new_request)
		return FAILURE;
	new_request->target = target;
	new_request->port = port;

	new_request->type = scan_type;
	new_request->id = id;
	new_request->retries = 0;

	new_request->next = NULL;
	new_request->prev = *tail;
	// update next of current tail or head if list is empty
	if (*tail)
		(*tail)->next = new_request;
	else
		*head = new_request;
	*tail = new_request;

	return SUCCESS;
}

t_probe *get_our_probe_request(t_probe **head, t_probe **tail, u16 source_port,
							   struct in_addr ip_src, t_scan_type scan_type,
							   u16 *nb_probes)
{
	t_probe *tmp = *head;

	/* The source port contained in the IP header of the response is the port we
	sent a probe to. Since our program can run multiple types of scan TCP at
	once we use the destination port contained in the IP header to find back
	which type of scan was used by the probe.

	See determine_tcp_scan_type() and g_port_range_tcp in
	determine_tcp_scan_type.c
	*/
	while (tmp)
	{
		if (source_port == tmp->port && scan_type == tmp->type
			&& ip_src.s_addr == tmp->target->addr.s_addr)
		{
			break;
		}
		tmp = tmp->next;
	}
	if (tmp)
	{
		erase_reference_to_node(head, tail, tmp, nb_probes);
	}
	return tmp;
}

bool probe_in_queue(const t_probe *head, u16 port, t_scan_type type,
					struct in_addr ip)
{
	for (const t_probe *tmp = head; tmp; tmp = tmp->next)
	{
		if (tmp->port == port && tmp->type == type
			&& tmp->target->addr.s_addr == ip.s_addr)
			return true;
	}
	return false;
}
