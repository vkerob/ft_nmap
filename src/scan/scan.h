#ifndef SCAN_H
#define SCAN_H

#define HIGHEST_PORT_STATE 5

#include "args.h"
#include "defines.h"
#include "typesdef.h"

#include <net/if.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdbool.h>

typedef enum e_port_state
{
	OPEN = 1,
	CLOSE,
	FILTERED,
	UNFILTERED,
	OPEN_FILTERED,
	UNKNOWN,
} t_port_state;

typedef struct s_port
{
	u16				port_number;
	t_port_state	port_state;
} t_port;

typedef struct s_port_list
{
	/* Store the index of the port inside port_map_rev array and port_final_state array or 0 if the port is not scanned */
	u16	   *port_map;
	/* Store the state of each port for each type of scan*/
	t_port *port_map_rev[MAX_NB_SCAN_TYPE];
	/* Store the final state of each port */
	t_port_state *port_final_state;
	/* Number of port in each state (open, filtered, ...) */
	int state_count[HIGHEST_PORT_STATE];
} t_port_list;

typedef struct s_iface_info
{
	char		   name[IFNAMSIZ];
	struct in_addr ip_addr; // ip of the interface, used as source ip in packets
	struct ether_addr mac_addr;	   // not defined yet, mac of the interface.
	u8				  iface_index; // index of the interface
} t_iface_info;

typedef struct s_program_info
{
	struct timeval start;
} t_program_info;



typedef struct s_target
{
	char		  *input;
	struct in_addr addr;
	t_port_list	   port_list;
	t_iface_info  *iface_info;
} t_target;

typedef enum e_scan_type
{
	SCAN_SYN = 0,
	SCAN_NULL,
	SCAN_ACK,
	SCAN_FIN,
	SCAN_XMAS,
	SCAN_UDP,
	SCAN_UNKNOWN
} t_scan_type;

typedef struct s_port_range_scan_type
{
	t_scan_type scan_type;
	u16			min_port_range;
	u16			max_port_range;
} t_port_range_scan_type;

typedef struct s_ctx
{
	t_target	  *targets;
	size_t		   target_count;
	t_iface_info  *ifaces;
	size_t		   iface_count;
	t_args		   args;
	t_program_info program_info;
	pcap_t		 **handles;
} t_ctx;

bool init_portlist(t_port_list *port_list, u16 port_count,
				   u16 ports[MAX_PORT_COUNT], u8 scan_types[MAX_NB_SCAN_TYPE],
				   u8 nb_scan_type);

bool link_port_list_to_each_target(t_ctx *ctx);

void scan_type_to_str(t_scan_type scan_type, char buf[16]);

bool get_iface_info(t_iface_info **ifaces, size_t *iface_count,
					t_target *targets, size_t target_count);

void print_scan_results(t_ctx *ctx);

#endif
