#ifndef ARGS_H
#define ARGS_H

#include "defines.h"
#include "typesdef.h"

#include <stdbool.h>

typedef struct	s_args
{
	u16				flags;
	u16				ports[MAX_PORT_COUNT];
	u16				port_count;
	u8				scan_types[MAX_NB_SCAN_TYPE];
	u8				nb_scan_types;
	u16				max_port_nb;
	u8				nb_scan;
	u8				speed;
	/* Indicate whether we have a UDP and TCP scan among scan_types so we don't have to loop over scan_types we 
	need that information */
	bool			tcp_scan;
	bool			udp_scan;
}	t_args;
#endif
