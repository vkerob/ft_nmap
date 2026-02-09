#include "shared.h"

#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>

void initialize_shared_data(
							t_shared_data *shared_data,
							pcap_t *handle,
							t_ctx *ctx)
{
	shared_data->handle = handle;
	atomic_init(&shared_data->id, 1);
	atomic_init(&shared_data->base_port, 32768 + (rand() % (65535 - 32768)));
	atomic_init(&shared_data->base_seq, rand());

	strncpy(shared_data->source_ip, ctx->source_ip, INET_ADDRSTRLEN);
	memset(shared_data->gateway_mac, 0, ETH_ALEN);
	pthread_mutex_init(&shared_data->mutex, NULL);
	shared_data->request_list_head = NULL;
	shared_data->request_list_tail = NULL;
	shared_data->nb_probe_requests = 0;
	shared_data->targets = ctx->targets;
	shared_data->target_count = ctx->target_count;
	shared_data->port_count = ctx->args.port_count;
	shared_data->targets = ctx->targets;
}
