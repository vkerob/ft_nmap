#include "ft_nmap.h"
#include <pthread.h>

void *pcap_capture(void *arg)
{
	t_shared_data *shared_data = (t_shared_data *)arg;
	pcap_t		 *handle = shared_data->handle;

	

	while (1)
	{
		struct pcap_pkthdr *header;
		const u_char	   *packet;
		int				   res = pcap_next_ex(handle, &header, &packet);
		if (res == 0)
			continue; // timeout elapsed
		if (res == -1)
		{
			fprintf(stderr, "ft_nmap: pcap_next_ex error: %s\n",
					pcap_geterr(handle));
			break;
		}
		if (res == -2)
		{
			// No more packets in savefile
			break;
		}

		// Process the captured packet
		// For example, parse the packet and send relevant info to the message queue
	}


	return NULL;
}