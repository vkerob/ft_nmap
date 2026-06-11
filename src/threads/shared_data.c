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
		LOG("ft_nmap: calloc failed: %s\n", strerror(errno));
		return true;
	}

	for (size_t i = 0; i < ctx->iface_count; i++)
	{
		int res = pthread_mutex_init(&shared_data_probe->sent[i].safe_mut.mutex, NULL);
		if (res != 0)
		{
			LOG("ft_nmap: pthread_mutex_init: %s\n", strerror(res));
			return true;
		}
		shared_data_probe->sent[i].safe_mut.initialize = true;
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
	shared_data_probe->args = &ctx->args;

	atomic_init(&shared_data_probe->id, 1);
	atomic_init(&shared_data_probe->base_seq, rand());

	int res = pthread_mutex_init(&shared_data_probe->to_send.safe_mut.mutex, NULL);
	if (res != 0)
	{
		LOG("ft_nmap: pthread_mutex_init: %s\n", strerror(res));
		return true;
	}
	shared_data_probe->to_send.safe_mut.initialize = true;

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
		LOG("ft_nmap: calloc failed: %s\n", strerror(errno));
		return true;
	}

	for (size_t i = 0; i < iface_count; i++)
	{
		(*pcap_ctxs)[i].iface_info = &ifaces[i];
		(*pcap_ctxs)[i].to_send = &shared_data_probe->to_send;
		(*pcap_ctxs)[i].sent = &shared_data_probe->sent[i];
		(*pcap_ctxs)[i].handle = NULL;
		(*pcap_ctxs)[i].args = shared_data_probe->args;
		(*pcap_ctxs)[i].program_info = program_info;
	}
	return false;
}

static void free_probes(t_probe *head)
{
	t_probe *tmp = head;
	t_probe *next;

	while (tmp)
	{
		next = tmp->next;
		free(tmp);
		tmp = next;
	}
}


void safe_destroy_mutex(t_safe_mutex *safe_mutex)
{
	if (safe_mutex->initialize)
	{
		pthread_mutex_destroy(&safe_mutex->mutex);
		safe_mutex->initialize = false;
	}
}

static void free_sent_queues(size_t iface_count, t_probe_queue *sent_queues)
{
	for (size_t i = 0; i < iface_count; i++)
	{
		// If we stopped the program before it ends, sent list may contain
		// t_probe objects
		if (sent_queues[i].nb_probe > 0)
		{
			free_probes(sent_queues[i].head);
		}
		safe_destroy_mutex(&sent_queues[i].safe_mut);
	}
	free(sent_queues);
}

static void free_to_send_queue(t_probe_queue *to_send_queue)
{
	if (to_send_queue->nb_probe > 0)
	{
		free_probes(to_send_queue->head);
	}
	safe_destroy_mutex(&to_send_queue->safe_mut);
}

void deinitialize_shared_data(t_shared_data_sender *shared_data_probe,
							  t_ctx				   *ctx)
{
	free_sent_queues(ctx->iface_count, shared_data_probe->sent);
	free_to_send_queue(&shared_data_probe->to_send);
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
