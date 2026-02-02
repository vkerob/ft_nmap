#include "ft_nmap.h"
#include <pthread.h>

static void print_debug_probe_request(t_probe_request *request)
{

	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
	printf(ANSI_BOLD ANSI_COLOR_CYAN "New Probe Request:\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_GREEN
		   "--------------------------------------------\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_GREEN "  • Target: %s:%u\n" ANSI_COLOR_RESET,
		   request->target.ip, request->target.port);
	printf(ANSI_COLOR_GREEN "  • Type: %d\n" ANSI_COLOR_RESET, request->type);
	printf(ANSI_COLOR_GREEN "  • ID: %u\n" ANSI_COLOR_RESET, request->id);
	printf(ANSI_COLOR_CYAN
		   "============================================\n" ANSI_COLOR_RESET);
}

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

void initialize_shared_data(t_shared_data *shared_data, pcap_t *handle,
							char *source_ip)
{
	shared_data->handle = handle;
	atomic_init(&shared_data->id, 1);
	atomic_init(&shared_data->base_port, 32768 + (rand() % (65535 - 32768)));
	atomic_init(&shared_data->base_seq, rand());

	strncpy(shared_data->source_ip, source_ip, INET_ADDRSTRLEN);
	memset(shared_data->gateway_mac, 0, ETH_ALEN);
	pthread_mutex_init(&shared_data->mutex, NULL);
	shared_data->request_list_head = NULL;
	shared_data->request_list_tail = NULL;
}

bool run_scan(t_ctx *ctx)
{
	pcap_t	   *handle;
	char		errbuf[PCAP_ERRBUF_SIZE];
	const char *dev_name = ctx->dev_name;
	t_target	first_target = ctx->targets[0];

	if (HAS(ctx->args.flags, F_SPOOF))
	{
		printf(ANSI_BOLD ANSI_COLOR_YELLOW
			   "[*] Spoofing enabled (bonus feature)\n" ANSI_COLOR_RESET);
		// get gateway MAC address for ethernet header, arp request if needed
	}

	if (pcap_setup(&handle, dev_name, ctx->source_ip, errbuf, first_target))
		return true;

	pthread_t	  pcap_thread;
	pthread_t	  send_thread;
	t_shared_data shared_data;

	initialize_shared_data(&shared_data, handle, ctx->source_ip);

	initial_probe_requests(ctx->targets, ctx->target_count, ctx->args.ports,
						   ctx->args.port_count, ctx->args.scan_type,
						   &shared_data.request_list_head,
						   &shared_data.request_list_tail);

	// launch thread to handle captured packets
	pthread_create(&pcap_thread, NULL, pcap_capture, &shared_data);

	// launch thread to send packets
	pthread_create(&send_thread, NULL, send_packet, &shared_data);

	pthread_join(pcap_thread, NULL);

	pthread_join(send_thread, NULL);

	free_requests_list(&shared_data.request_list_head);
	pthread_mutex_destroy(&shared_data.mutex);
	pcap_close(handle);

	return false;
}