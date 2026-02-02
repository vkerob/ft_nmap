#include "ft_nmap.h"
#include <pthread.h>
#include <sys/select.h>

void *pcap_capture(void *arg)
{
	t_shared_data *shared_data = (t_shared_data *)arg;
	pcap_t		  *handle = shared_data->handle;
	int			   pcap_fd = pcap_get_selectable_fd(handle);
	fd_set		   read_fds;

	int max_fd = (pcap_fd > g_pipefd[0]) ? pcap_fd : g_pipefd[0];

	while (!g_stop)
	{
		FD_ZERO(&read_fds);
		FD_SET(pcap_fd, &read_fds);
		FD_SET(g_pipefd[0], &read_fds);

		int ret = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
		if (ret == -1)
		{
			perror("select");
			break;
		}
		if (ret > 0)
		{
			if (FD_ISSET(g_pipefd[0], &read_fds))
			{
				if (g_stop)
					break;
			}
			if (FD_ISSET(pcap_fd, &read_fds))
			{
				printf("pcap_fd set in reads_fds\n");
				t_pcap_user_data user_data;
				user_data.handle = handle;
				print_debug_packet_start();
				pcap_dispatch(handle, 1, handle_packet, (u_char *)&user_data);
				print_debug_packet_end();
			}
		}
	}

	return NULL;
}