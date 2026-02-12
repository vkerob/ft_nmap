#include "shared.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

bool initialize_shared_data_probe(t_shared_data_probe *shared_data_probe,
								  t_ctx				  *ctx)
{

	shared_data_probe->pending_request_list_mut
		= calloc(ctx->iface_count, sizeof(pthread_mutex_t));
	if (shared_data_probe->pending_request_list_mut == NULL)
	{
		return true;
	}
	shared_data_probe->pending_request_head
		= calloc(ctx->iface_count, sizeof(t_probe_request *));
	if (shared_data_probe->pending_request_head == NULL)
	{
		return true;
	}
	shared_data_probe->pending_request_tail
		= shared_data_probe->pending_request_head;

	// shared_data_probe->handles = ctx->handles;
	atomic_init(&shared_data_probe->id, 1);
	atomic_init(&shared_data_probe->base_seq, rand());
	atomic_init(&shared_data_probe->nb_probe_requests, 0);
	atomic_init(&shared_data_probe->nb_probe_requests_done, 0);

	shared_data_probe->request_list_head = NULL;
	shared_data_probe->request_list_tail = NULL;
	shared_data_probe->targets = ctx->targets;
	shared_data_probe->target_count = ctx->target_count;
	shared_data_probe->port_count = ctx->args.port_count;
	shared_data_probe->targets = ctx->targets;
	shared_data_probe->nb_probe_requests_initial
		= shared_data_probe->nb_probe_requests;

	for (size_t i = 0; i < ctx->iface_count; i++)
	{
		pthread_mutex_init(&shared_data_probe->pending_request_list_mut[i],
						   NULL);
	}
	pthread_mutex_init(&shared_data_probe->request_list_mut, NULL);

	// shared_data_probe->pending_request_tail
	// 	= calloc(ctx->iface_count, sizeof(t_probe_request *));
	// if (shared_data_probe->pending_request_tail == NULL)
	// {
	// 	return true;
	// }
	// shared_data_probe->pending_request_list_mut
	// 	= calloc(ctx->iface_count, sizeof(pthread_mutex_t));
	// if (shared_data_probe->pending_request_list_mut == NULL)
	// {
	// 	return true;
	// }

	return false;
}

void initialize_shared_data_pcap(t_shared_data_pcap_thread *shared_data_pcap,
								 t_shared_data_probe	   *shared_data_probe)
{
	shared_data_pcap->request_list_head = shared_data_probe->request_list_head;
	shared_data_pcap->request_list_tail = shared_data_probe->request_list_tail;
	shared_data_pcap->nb_probe_requests = shared_data_probe->nb_probe_requests;
	shared_data_pcap->nb_probe_requests_initial
		= shared_data_probe->nb_probe_requests;
}

void deinitialize_shared_data_probe(t_shared_data_probe *shared_data_probe,
									pcap_t **handles, t_ctx *ctx)
{
	for (size_t i = 0; i < ctx->iface_count; i++)
	{
		pthread_mutex_destroy(&shared_data_probe->pending_request_list_mut[i]);
	}
	free(shared_data_probe->pending_request_list_mut);
	free(shared_data_probe->pending_request_head);
	free(shared_data_probe->pending_request_tail);
	pthread_mutex_destroy(&shared_data_probe->request_list_mut);

	for (size_t i = 0; i < ctx->iface_count; i++)
	{
		pcap_close(handles[i]);
	}
}
