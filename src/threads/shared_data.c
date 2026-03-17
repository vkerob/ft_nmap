#include "shared.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

bool initialize_shared_data_probe(t_shared_data_sender *shared_data_probe,
								  t_ctx				   *ctx)
{
	// init the sent request list for each interface
	shared_data_probe->sent = calloc(ctx->iface_count, sizeof(t_probe_queue));
	if (!shared_data_probe->sent)
	{
		fprintf(stderr, "ft_nmap: calloc failed: %s\n", strerror(errno));
		return true;
	}

	for (size_t i = 0; i < ctx->iface_count; i++)
	{
		int res = pthread_mutex_init(&shared_data_probe->sent[i].mut, NULL);
		if (res != 0)
		{
			fprintf(stderr, "ft_nmap: pthread_mutex_init: %s\n", strerror(res));
			return true;
		}
		shared_data_probe->sent[i].nb_probe = 0;
		shared_data_probe->sent[i].head = NULL;
		shared_data_probe->sent[i].tail = NULL;
	}

	// init the probe request list
	shared_data_probe->iface_count = ctx->iface_count;
	shared_data_probe->port_count = ctx->args.port_count;
	shared_data_probe->to_send.head = NULL;
	shared_data_probe->to_send.tail = NULL;
	shared_data_probe->to_send.nb_probe = 0;
	shared_data_probe->program_info = &ctx->program_info;

	atomic_init(&shared_data_probe->id, 1);
	atomic_init(&shared_data_probe->base_seq, rand());

	int res = pthread_mutex_init(&shared_data_probe->to_send.mut, NULL);
	if (res != 0)
	{
		fprintf(stderr, "ft_nmap: pthread_mutex_init: %s\n", strerror(res));
		return true;
	}

	return false;
}

bool initialize_receiver_data(t_receiver_data **pcap_ctxs, size_t iface_count,
							  t_shared_data_sender *shared_data_probe,
							  t_iface_info		   *ifaces,
							  t_program_info	   *program_info)
{
	*pcap_ctxs = calloc(iface_count, sizeof(t_receiver_data));
	if (!*pcap_ctxs)
	{
		fprintf(stderr, "ft_nmap: calloc failed: %s\n", strerror(errno));
		return true;
	}

	for (size_t i = 0; i < iface_count; i++)
	{
		(*pcap_ctxs)[i].iface_info = &ifaces[i];
		(*pcap_ctxs)[i].to_send = &shared_data_probe->to_send;
		(*pcap_ctxs)[i].sent = &shared_data_probe->sent[i];
		(*pcap_ctxs)[i].handle = NULL;
		(*pcap_ctxs)[i].program_info = program_info;
	}
	return false;
}

void deinitialize_shared_data(t_shared_data_sender *shared_data_probe,
							  t_ctx				   *ctx)
{
	for (size_t i = 0; i < ctx->iface_count; i++)
	{
		pthread_mutex_destroy(&shared_data_probe->sent[i].mut);
	}
	free(shared_data_probe->sent);
	pthread_mutex_destroy(&shared_data_probe->to_send.mut);
}

bool initialize_to_send_queue(t_ctx *ctx, t_probe_queue *to_send)
{
	to_send->head = NULL;
	to_send->tail = NULL;
	for (size_t i = 0; i < ctx->target_count; i++)
	{
		for (u16 j = 0; j < ctx->args.port_count; j++)
		{
			for (u8 k = 0; k < ctx->args.nb_scan_types; k++)
			{
				// Create and initialize a probe request for targets[i] and
				// ports[j] Append it to the linked list
				if (append_probe_request(
						&to_send->head, &to_send->tail, &ctx->targets[i],
						ctx->args.ports[j], ctx->args.scan_types[k],
						(u32)(i * ctx->args.port_count
							  + j * ctx->args.nb_scan_types + k)))
				{
					return true;
				}
				to_send->nb_probe++;
			}
		}
	}

	return false;
}

void free_requests_list(t_probe **head)
{
	t_probe *current = *head;
	while (current)
	{
		t_probe *next = current->next;
		free(current);
		current = next;
	}
	*head = NULL;
}
