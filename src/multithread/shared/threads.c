#include "capture.h"
#include "send.h"
#include "shared.h"

#include <errno.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

bool initialize_and_launch_threads(size_t nb_pcap_thread, u8 nb_send_thread,
								   pthread_t	**pcap_threads,
								   pthread_t	**send_threads,
								   t_shared_data *shared_data, char (*iface_names)[IFNAMSIZ])
{
	*pcap_threads = calloc(nb_pcap_thread, sizeof(pthread_t));
	if (*pcap_threads == NULL)
	{
		fprintf(stderr, "ft_nmap: calloc failed: %s\n", strerror(errno));
		return true;
	}
	*send_threads = calloc(nb_send_thread, sizeof(pthread_t));
	if (*send_threads == NULL)
	{
		fprintf(stderr, "ft_nmap: calloc failed: %s\n", strerror(errno));
		free(*pcap_threads);
		return true;
	}
	// launch thread to handle captured packets
	for (size_t i = 0; i < nb_pcap_thread; i++)
	{

		char errbuf[PCAP_ERRBUF_SIZE];
		if (pcap_setup(&shared_data->handle, iface_names[i], errbuf))
			return true;

		int ret = pthread_create(&(*pcap_threads)[i], NULL, receive_routine,
								 shared_data);
		if (ret != 0)
		{
			free(*send_threads);
			free(*pcap_threads);
			fprintf(stderr, "ft_nmap: pthread_create failed: %s\n",
					strerror(ret));
			return true;
		}
	}

	// launch thread to send packets
	for (u8 i = 0; i < nb_send_thread; i++)
	{
		int ret
			= pthread_create(&(*send_threads)[i], NULL, send_routine, shared_data);
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

	for (u8 i = 0; i < nb_send_threads; i++)
	{
		pthread_join((*send_threads)[i], NULL);
	}

	free(*pcap_threads);
	free(*send_threads);
}
