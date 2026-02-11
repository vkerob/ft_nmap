#include "shared.h"

#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>

bool	initialize_shared_data(
	t_shared_data *shared_data,
	pcap_t **handles,
	t_ctx *ctx)
{
	shared_data->handles = handles;
	atomic_init(&shared_data->id, 1);
	atomic_init(&shared_data->base_seq, rand());

	strncpy(shared_data->source_ip, ctx->source_ip, INET_ADDRSTRLEN);
	memset(shared_data->gateway_mac, 0, ETH_ALEN);
	shared_data->request_list_head = NULL;
	shared_data->request_list_tail = NULL;
	shared_data->nb_probe_requests = 0;
	shared_data->targets = ctx->targets;
	shared_data->target_count = ctx->target_count;
	shared_data->port_count = ctx->args.port_count;
	shared_data->targets = ctx->targets;

	shared_data->pending_request_head = calloc(ctx->iface_count, sizeof(t_probe_request *));
	if (shared_data->pending_request_head == NULL)
	{
		return true;
	}
	shared_data->pending_request_tail = calloc(ctx->iface_count, sizeof(t_probe_request *));
	if (shared_data->pending_request_tail == NULL)
	{
		return true;
	}
	for (size_t i = 0; i < ctx->iface_count; i++)
	{
		pthread_mutex_init(&shared_data->pending_request_list_mut[i], NULL);
	}
	pthread_mutex_init(&shared_data->request_list_mut, NULL);
	return false;
}

void	deinitialize_shared_data(
	t_shared_data *shared_data,
	pcap_t **handles,
	t_ctx *ctx)
{
	for (size_t i = 0; i < ctx->iface_count; i++)
	{
		pthread_mutex_destroy(&shared_data->pending_request_list_mut[i]);
	}
	free(shared_data->pending_request_list_mut);

	for (size_t i = 0; i < ctx->iface_count; i++)
	{
		pcap_close(handles[i]);
	}
}

