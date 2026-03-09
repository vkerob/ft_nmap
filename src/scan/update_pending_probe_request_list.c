#include "request.h"

#include <stddef.h>
#include <stdlib.h>

bool update_pending_probe_request_list(t_request **head_pending_list,
									   t_request **tail_pending_list,
									   t_request  *request,
									   time_t	   sent_timestamp)
{
	request->timestamp = sent_timestamp;
	request->retries = request->retries + 1;
	request->next = NULL;
	request->prev = NULL;
	if (*head_pending_list == NULL)
	{
		*head_pending_list = request;
	}
	else
	{
		(*tail_pending_list)->next = request;
		request->prev = *tail_pending_list;
	}
	*tail_pending_list = request;
	return false;
}
