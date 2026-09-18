#ifndef ARGS_H
#define ARGS_H

#include "defines.h"
#include "typesdef.h"

#include <netinet/in.h>
#include <stdbool.h>

typedef struct s_args
{
	u16 flags;
	/* Can't be an array of u16 even though the max port is 65535 because we use
	-1 as the value to represent a port that is not part of our scan since 0 is
	a valid port numbers*/
	int *port_map;
	u16	 ports[MAX_PORT_COUNT];
	u16	 port_count;
	u8	 scan_types[MAX_NB_SCAN_TYPE];
	u8	 nb_scan_types;
	/* Maximum port number we have*/
	u16 max_port_nb;
	u8	speed;
	/* Indicate whether we have a UDP and TCP scan among scan_types so we don't
	have to loop over scan_types we need that information */
	bool		   tcp_scan;
	bool		   udp_scan;
	struct in_addr decoys[MAX_DECOYS];
	u8			   decoy_count;
	u8			   max_retries;
	double		   timeout_ms;
	double		   timeout_s;
} t_args;

#endif
