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

bool pcap_setup(pcap_t **handle, const char *iface_name, char *errbuf,
				const char *ip_src_interface);

void handle_packet(u_char *args, const struct pcap_pkthdr *header,
				   const u_char *packet);

void *capture_routine(void *arg);

#endif
