#ifndef SETUP_H
#define SETUP_H

#include <net/if.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <sys/ioctl.h>

int set_pcap_filter(pcap_t *interface);

bool setup_pcap_handles(pcap_t **handles, size_t iface_count,
						char (*iface_names)[IFNAMSIZ]);

bool pcap_setup(pcap_t **handle, const char *iface_name, char *errbuf);
#endif
