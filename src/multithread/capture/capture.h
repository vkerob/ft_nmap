#ifndef CAPTURE_H
#define CAPTURE_H

#include "defines.h"
#include "shared.h"
#include "typesdef.h"

#include <pcap/pcap.h>

typedef struct s_pcap_user_data
{
	pcap_t					  *handle;
	t_shared_data_pcap_thread *shared_data;
} t_pcap_user_data;

bool pcap_setup(pcap_t **handle, const char *dev_name, char *errbuf);

void handle_packet(u_char *args, const struct pcap_pkthdr *header,
				   const u_char *packet);

void *receive_routine(void *arg);

#endif
