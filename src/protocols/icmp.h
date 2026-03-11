#ifndef ICMP_H
#define ICMP_H

#include "scan.h"
#include "typesdef.h"

#include <netinet/ip_icmp.h>

void handle_icmp_response(t_target *target);

#endif