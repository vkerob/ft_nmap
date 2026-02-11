#include "probe_request.h"

#include <stdlib.h>
#include <string.h>

bool pop_probe_request(t_probe_request **head, t_probe_request **tail,
					   t_probe_request **popped_request)
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

bool append_probe_request(t_probe_request **head, t_probe_request **tail,
						  t_target target, u16 port, enum e_scan_type scan_type,
						  u32 id)
{
	t_probe_request *new_request = malloc(sizeof(t_probe_request));
	if (!new_request)
		return true;
	strncpy(new_request->target.ip, target.ip, INET_ADDRSTRLEN);
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

bool initial_probe_requests(t_ctx *ctx, t_probe_request **head,
							t_probe_request **tail)
{
	*head = NULL;
	*tail = NULL;
	for (size_t i = 0; i < ctx->target_count; i++)
	{
		for (u16 j = 0; j < ctx->args.port_count; j++)
		{
			for (u8 k = 0; k < ctx->args.nb_scan_types; k++)
			{
				// Create and initialize a probe request for targets[i] and
				// ports[j] Append it to the linked list
				append_probe_request(head, tail, ctx->targets[i],
									 ctx->args.ports[j],
									 (enum e_scan_type)ctx->args.scan_types[k],
									 (u32)(i * ctx->args.port_count + j));
			}
		}
	}

	return false;
}

void free_requests_list(t_probe_request **head)
{
	t_probe_request *current = *head;
	while (current)
	{
		t_probe_request *next = current->next;
		free(current);
		current = next;
	}
	*head = NULL;
}
