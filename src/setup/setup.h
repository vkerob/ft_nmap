#ifndef SETUP_H
#define SETUP_H

#include "scan.h"

#include <net/if.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <sys/ioctl.h>

int set_pcap_filter(pcap_t *interface);

bool setup_pcap_handles(pcap_t **handles, size_t iface_count,
						t_iface_info *finfos);
#endif
