#ifndef SETUP_H
#define SETUP_H

#include <pcap/pcap.h>
#include <stdbool.h>

int		set_pcap_filter(pcap_t *interface);

bool	pcap_select_interface(char **dev_name, char *my_ip);

#endif
