#include "request.h"

#include <stddef.h>
#include <stdlib.h>

bool add_to_probe_queue(t_probe **head_sent_list, t_probe **tail_sent_list,
					   t_probe *request, struct timeval sent_timestamp)
{
	request->timestamp = sent_timestamp;
	// request->retries = request->retries + 1;
	request->next = NULL;
	request->prev = NULL;
	if (*head_sent_list == NULL)
	{
		*head_sent_list = request;
	}
	else
	{
		(*tail_sent_list)->next = request;
		request->prev = *tail_sent_list;
	}
	*tail_sent_list = request;
	return false;
}
