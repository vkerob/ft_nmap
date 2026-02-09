#ifndef ETHERNET_H
#define ETHERNET_H

#include "typesdef.h"

#include <netinet/if_ether.h>
#include <net/ethernet.h>

void build_ethernet_header(struct ether_header *eth_hdr);

#endif
