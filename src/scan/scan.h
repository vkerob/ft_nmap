#ifndef SCAN_H
#define SCAN_H

#include "defines.h"
#include "typesdef.h"
#include "args.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>

typedef struct s_port
{
	u16	port_number;
	u8	proto;
	u8	port_state;
}	t_port;

typedef struct t_port_list
{
	u16			*port_map[MAX_NB_SCAN_TYPE];
	t_port	*port_map_rev[MAX_NB_SCAN_TYPE];
}	t_port_list;

typedef struct s_target
{
	char								*input;
	char								ip[INET_ADDRSTRLEN];
	t_port_list					port_list;
	struct sockaddr_in	addr;
}	t_target;

typedef enum e_scan_type
{
	SCAN_SYN = 0,
	SCAN_NULL,
	SCAN_ACK,
	SCAN_FIN,
	SCAN_XMAS,
	SCAN_UDP,
	SCAN_UNKNOWN
}	t_scan_type;

typedef struct	s_port_range_scan_type
{
	t_scan_type	scan_type;
	u16					min_port_range;
	u16					max_port_range;
}	t_port_range_scan_type;

typedef enum	e_port_state {
	OPEN = 1,
	CLOSE,
	FILTERED,
	UNFILTERED,
	OPEN_FILTERED,
	CLOSE_FILTERED,
	UNKNOWN,
}	t_port_state;

typedef struct	s_ctx
{
	t_target			*targets;
	size_t				target_count;
	char					source_ip[INET_ADDRSTRLEN];
	char					*dev_name;
	t_args				args;
}	t_ctx;


bool	run_scan(t_ctx *ctx);

void	create_port(u16 port_number, u8 proto, t_port *port);

bool	init_portlist(
	t_port_list *port_list,
	u16 port_count,
	u16 ports[MAX_PORT_COUNT],
	u8 nb_scan_types,
	u8 scan_types[MAX_NB_SCAN_TYPE]);

#endif
