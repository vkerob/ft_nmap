#ifndef CAPTURE_H
#define CAPTURE_H

#include "shared.h"
#include "typesdef.h"

#include <pcap/pcap.h>
extern pthread_mutex_t printf_mutex;
typedef struct s_pcap_user_data
{
	pcap_t			*handle;
	t_receiver_data *receiver_data;
} t_pcap_user_data;

int pcap_setup(t_receiver_data *pcap_ctx, char *errbuf, t_target *targets,
				size_t target_count);

void handle_packet(u_char *args, const struct pcap_pkthdr *header,
				   const u_char *packet);

void *capture_routine(void *arg);

#endif
