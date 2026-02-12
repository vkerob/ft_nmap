#ifndef SETUP_H
#define SETUP_H

#include <net/if.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <sys/ioctl.h>

int set_pcap_filter(pcap_t *interface);

bool pcap_setup(pcap_t **handle, const char *iface_name, char *errbuf);
#endif
