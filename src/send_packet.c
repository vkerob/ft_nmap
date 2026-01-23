#include "ft_nmap.h"
#include <mqueue.h>
#include <pthread.h>

void *send_packet(void *arg)
{
	t_shared_data *shared_data = (t_shared_data *)arg;
	(void)shared_data;

	return NULL;
}