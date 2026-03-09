#include "shared.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

bool initialize_shared_data_probe(t_shared_data_probe *shared_data_probe,
								  t_ctx				  *ctx)
{
	// init the pending request list for each interface
	shared_data_probe->pending_request_list
		= calloc(ctx->iface_count, sizeof(t_pending_queue));
	if (!shared_data_probe->pending_request_list)
		return true;

	for (size_t i = 0; i < ctx->iface_count; i++)
	{
		pthread_mutex_init(&shared_data_probe->pending_request_list[i].mut,
						   NULL);
		shared_data_probe->pending_request_list[i].nb_pending_requests = 0;
		shared_data_probe->pending_request_list[i].head = NULL;
		shared_data_probe->pending_request_list[i].tail = NULL;
	}

	// init the probe request list
	shared_data_probe->iface_count = ctx->iface_count;
	shared_data_probe->port_count = ctx->args.port_count;
	shared_data_probe->probe_request_list.head = NULL;
	shared_data_probe->probe_request_list.tail = NULL;
	shared_data_probe->probe_request_list.nb_probe_requests = 0;

	atomic_init(&shared_data_probe->id, 1);
	atomic_init(&shared_data_probe->base_seq, rand());


	pthread_mutex_init(&shared_data_probe->probe_request_list.mut, NULL);
	return false;
}

bool initialize_shared_data_pcap(t_shared_data_pcap **pcap_ctxs,
								 size_t				  iface_count,
								 t_shared_data_probe *shared_data_probe,
								 t_iface_info		 *ifaces)
{
	*pcap_ctxs = calloc(iface_count, sizeof(t_shared_data_pcap));
	if (!*pcap_ctxs)
		return true;

	for (size_t i = 0; i < iface_count; i++)
	{
		(*pcap_ctxs)[i].iface_info = ifaces[i];
		(*pcap_ctxs)[i].probe_request_list
			= &shared_data_probe->probe_request_list;
		(*pcap_ctxs)[i].pending_request_list
			= &shared_data_probe->pending_request_list[i];
		(*pcap_ctxs)[i].handle = NULL;
	}
	return false;
}

void deinitialize_shared_data_probe(t_shared_data_probe *shared_data_probe,
									pcap_t **handles, t_ctx *ctx)
{
	for (size_t i = 0; i < ctx->iface_count; i++)
	{
		pthread_mutex_destroy(&shared_data_probe->pending_request_list[i].mut);
	}
	free(shared_data_probe->pending_request_list);
	pthread_mutex_destroy(&shared_data_probe->probe_request_list.mut);

	for (size_t i = 0; i < ctx->iface_count; i++)
	{
		pcap_close(handles[i]);
	}
}

bool initial_probe_request_list(t_ctx *ctx, t_request_list *probe_request_list)
{
	probe_request_list->head = NULL;
	probe_request_list->tail = NULL;
	for (size_t i = 0; i < ctx->target_count; i++)
	{
		for (u16 j = 0; j < ctx->args.port_count; j++)
		{
			for (u8 k = 0; k < ctx->args.nb_scan_types; k++)
			{
				// Create and initialize a probe request for targets[i] and
				// ports[j] Append it to the linked list
				if (append_probe_request(&probe_request_list->head,
										 &probe_request_list->tail,
										 ctx->targets[i], ctx->args.ports[j],
										 ctx->args.scan_types[k],
										 (u32)(i * ctx->args.port_count + j)))
				{
					return true;
				}
			}
		}
	}

	return false;
}

void free_requests_list(t_request **head)
{
	t_request *current = *head;
	while (current)
	{
		t_request *next = current->next;
		free(current);
		current = next;
	}
	*head = NULL;
}
