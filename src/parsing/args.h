#ifndef ARGS_H
#define ARGS_H

#include "defines.h"
#include "typesdef.h"

typedef struct	s_args
{
	u8				flags;
	u16				ports[MAX_PORT_COUNT];
	u16				port_count;
	u8				scan_types[MAX_NB_SCAN_TYPE];
	u8				nb_scan_types;
	u8				nb_scan;
	u8				speed;
}	t_args;
#endif
