#include "capture.h"
#include "debug.h"
#include "my_signal.h"
#include "send.h"
#include "shared.h"

#include <errno.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

int initialize_and_launch_threads(t_ctx *ctx, pthread_t **pcap_threads,
								  pthread_t			  **send_threads,
								  t_shared_data_sender *shared_data_probe,
								  t_receiver_data	   *pcap_ctxs)
{
	*pcap_threads = calloc(ctx->iface_count, sizeof(pthread_t));
	if (*pcap_threads == NULL)
	{
		LOG("ft_nmap: calloc failed: %s\n", strerror(errno));
		return FAILURE;
	}
	*send_threads = calloc(ctx->args.speed, sizeof(pthread_t));
	if (*send_threads == NULL)
	{
		LOG("ft_nmap: calloc failed: %s\n", strerror(errno));
		free(*pcap_threads);
		return FAILURE;
	}

	size_t created_pcap = 0;
	u8	   created_send = 0;

	// launch thread to handle captured packets
	for (size_t i = 0; i < ctx->iface_count; i++)
	{
		char errbuf[PCAP_ERRBUF_SIZE];
		if (pcap_setup(&pcap_ctxs[i], errbuf, ctx->targets, ctx->target_count))
			goto fail;

		if (pthread_create(&(*pcap_threads)[i], NULL, capture_routine,
						   &pcap_ctxs[i])
			!= 0)
		{
			LOG("ft_nmap: pthread_create failed\n");
			goto fail;
		}
		created_pcap++;
	}

	for (u8 i = 0; i < ctx->args.speed; i++)
	{
		if (pthread_create(&(*send_threads)[i], NULL, send_routine,
						   shared_data_probe)
			!= 0)
		{
			LOG("ft_nmap: pthread_create failed\n");
			goto fail;
		}
		created_send++;
	}
	return SUCCESS;

fail:
	/* Stop and reap whatever was already launched so they don't run on memory
	 * the caller is about to free. */
	g_stop = 1;
	for (size_t j = 0; j < created_pcap; j++)
		pthread_join((*pcap_threads)[j], NULL);
	for (u8 j = 0; j < created_send; j++)
		pthread_join((*send_threads)[j], NULL);
	for (size_t j = 0; j < created_pcap; j++)
	{
		if (pcap_ctxs[j].handle)
			pcap_close(pcap_ctxs[j].handle);
	}
	free(*pcap_threads);
	free(*send_threads);
	*pcap_threads = NULL;
	*send_threads = NULL;
	return FAILURE;
}

void join_and_free_threads(pthread_t **pcap_threads, pthread_t **send_threads,
						   u8 nb_send_threads, size_t nb_pcap_threads)
{
	for (size_t i = 0; i < nb_pcap_threads; i++)
	{
		pthread_join((*pcap_threads)[i], NULL);
	}

	// Once all capture threads have stopped we set g_stop to 1 to stop the
	// senders threads
	g_stop = 1;

	for (u8 i = 0; i < nb_send_threads; i++)
	{
		pthread_join((*send_threads)[i], NULL);
	}

	free(*pcap_threads);
	free(*send_threads);
}
