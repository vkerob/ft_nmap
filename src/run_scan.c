#include "ft_nmap.h"
#include <pthread.h>

bool append_probe_request(t_probe_request **head, t_probe_request **tail,
						  t_target target, uint16_t port,
						  enum e_scan_type scan_type, uint32_t id)
{
	t_probe_request *new_request = malloc(sizeof(t_probe_request));
	if (!new_request)
		return true;
	strncpy(new_request->target.ip, target.ip, INET_ADDRSTRLEN);
	new_request->target.port = port;
	new_request->type = scan_type;
	new_request->id = id;
	new_request->timestamp = 0;
	new_request->retries = 0;
	new_request->status = 0;

	new_request->next = NULL;
	// update next of current tail or head if list is empty
	if (*tail)
		(*tail)->next = new_request;
	else
		*head = new_request;
	// update tail to new request
	*tail = new_request;

	printf("Appended probe request: target=%s:%u, type=%d, id=%u\n",
		   new_request->target.ip, new_request->target.port, new_request->type,
		   new_request->id);

	return false;
}

bool initial_probe_requests(t_target *targets, size_t target_count,
							uint16_t *ports, size_t port_count,
							uint8_t scan_type, t_probe_request **head,
							t_probe_request **tail)
{
	*head = NULL;
	*tail = NULL;
	for (size_t i = 0; i < target_count; i++)
	{
		for (size_t j = 0; j < port_count; j++)
		{
			// Create and initialize a probe request for targets[i] and ports[j]
			// Append it to the linked list
			append_probe_request(head, tail, targets[i], ports[j],
								 (enum e_scan_type)scan_type,
								 (uint32_t)(i * port_count + j));
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

bool run_scan(t_ctx *ctx)
{
	pcap_t		  *handle;
	char		   errbuf[PCAP_ERRBUF_SIZE];
	const char	  *dev_name = ctx->dev_name;
	struct in_addr my_ip = ctx->my_ip;

	if (pcap_setup(&handle, dev_name, my_ip, errbuf))
		return true;

	pthread_t	  pcap_thread;
	pthread_t	  send_thread;
	t_shared_data shared_data;

	shared_data.handle = handle;
	initial_probe_requests(ctx->targets, ctx->target_count, ctx->args.ports,
						   ctx->args.port_count, ctx->args.scan_type,
						   &shared_data.request_list_head,
						   &shared_data.request_list_tail);

	free_requests_list(&shared_data.request_list_head);
	pcap_close(handle);
	return false;

	// launch thread to handle captured packets
	pthread_create(&pcap_thread, NULL, pcap_capture, &shared_data);

	// launch thread to send packets

	(void)send_thread;
	// pthread_create(&send_thread, NULL, send_packet, &shared_data);

	pthread_join(pcap_thread, NULL);

	// pcap_close(handle);

	return false;
}