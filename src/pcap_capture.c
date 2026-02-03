#include "ft_nmap.h"
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/select.h>

void *receive_routine(void *arg)
{
	t_shared_data	*shared_data = (t_shared_data *)arg;
	pcap_t			*handle = shared_data->handle;
	char			errbuf[PCAP_ERRBUF_SIZE];
	int				ret;

	const struct timeval *timeout = pcap_get_required_select_timeout(handle);
	if (timeout == NULL)
	{
		fprintf(stderr, "timeout not required\n");
	}
	else{
		printf("timeout seconds: %ld\n", timeout->tv_sec);
		fflush(stdout);
	}
	ret = pcap_setnonblock(handle, 1, errbuf);
	switch (ret)
	{
		case PCAP_ERROR_NOT_ACTIVATED:
			fprintf(stderr, "pcap_setnonblock: Capture handle is not activated\n");
			return NULL;
		case PCAP_ERROR:
			fprintf(stderr, "pcap_setnonblock: %s\n", errbuf);
			return NULL;
		default:
			break ;
	}

	while (!g_stop)
	{
		t_pcap_user_data user_data;
		user_data.handle = handle;
		/* Returns 0 if no packet to read */
		pcap_dispatch(handle, 1, handle_packet, (u_char *)&user_data);
	}

	return NULL;
}
