#include "probe_request.h"

#include <stddef.h>
#include <stdlib.h>

bool	update_pending_probe_request_list(
	t_probe_request_sent **head,
	t_probe_request_sent **tail,
	t_probe_request	*request,
	time_t sent_timestamp)
{
	t_probe_request_sent *request_with_metadata = calloc(1, sizeof(t_probe_request_sent));
	if (request_with_metadata == NULL)
	{
		return false;
	}
	request_with_metadata->request = request;
	request_with_metadata->timestamp = sent_timestamp;
	request_with_metadata->retries = request->retries + 1;
	if (*head == NULL)
	{
		*head = request_with_metadata;
	}
	else
	{
		(*tail)->next = request_with_metadata;
	}
	*tail = request_with_metadata;
	return true;
}