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

bool initialize_and_launch_threads(t_ctx *ctx, pthread_t **pcap_threads,
								   pthread_t		   **send_threads,
								   t_shared_data_sender *shared_data_probe,
								   t_receiver_data		*pcap_ctxs)
{
	*pcap_threads = calloc(ctx->iface_count, sizeof(pthread_t));
	if (*pcap_threads == NULL)
	{
		fprintf(stderr, "ft_nmap: calloc failed: %s\n", strerror(errno));
		return true;
	}
	*send_threads = calloc(ctx->args.speed, sizeof(pthread_t));
	if (*send_threads == NULL)
	{
		fprintf(stderr, "ft_nmap: calloc failed: %s\n", strerror(errno));
		free(*pcap_threads);
		return true;
	}
	// launch thread to handle captured packets
	for (size_t i = 0; i < ctx->iface_count; i++)
	{
		char errbuf[PCAP_ERRBUF_SIZE];
		if (pcap_setup(&pcap_ctxs[i], errbuf, ctx->targets, ctx->target_count))
			return true;
		// print_debug_receiver_data(&receiver_data[i]);

		int ret = pthread_create(&(*pcap_threads)[i], NULL, capture_routine,
								 &pcap_ctxs[i]);
		if (ret != 0)
		{
			free(*send_threads);
			free(*pcap_threads);
			fprintf(stderr, "ft_nmap: pthread_create failed: %s\n",
					strerror(ret));
			return true;
		}
	}

	// print_debug_shared_data_probe(shared_data_probe, ifaces);

	for (u8 i = 0; i < ctx->args.speed; i++)
	{
		int ret = pthread_create(&(*send_threads)[i], NULL, send_routine,
								 shared_data_probe);
		if (ret != 0)
		{
			fprintf(stderr, "ft_nmap: pthread_create failed: %s\n",
					strerror(ret));
			free(*send_threads);
			free(*pcap_threads);
			return true;
		}
	}
	return false;
}

void join_and_free_threads(pthread_t **pcap_threads, pthread_t **send_threads,
						   u8 nb_send_threads, size_t nb_pcap_threads)
{
	for (size_t i = 0; i < nb_pcap_threads; i++)
	{
		pthread_join((*pcap_threads)[i], NULL);
	}
	g_stop = 1;

	for (u8 i = 0; i < nb_send_threads; i++)
	{
		pthread_join((*send_threads)[i], NULL);
	}

	free(*pcap_threads);
	free(*send_threads);
}
