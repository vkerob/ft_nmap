#ifndef REQUEST_H
#define REQUEST_H

#include "scan.h"
#include "typesdef.h"

#include <arpa/inet.h>
#include <stdbool.h>

typedef struct s_probe
{
	t_target		*target;
	u16				 port;
	enum e_scan_type type;
	struct timeval	 timestamp;
	u32				 id;
	u8				 retries;
	struct s_probe	*prev;
	struct s_probe	*next;
} t_probe;

void print_debug_probe_request(const t_probe *request);

void pop_probe_request(t_probe **head, t_probe **tail,
					   t_probe **popped_request);

int append_probe_request(t_probe **head, t_probe **tail, t_target *target,
						 u16 port, t_scan_type scan_type, u32 id);

int add_to_probe_queue(t_probe **head_sent_list, t_probe **tail_sent_list,
					   t_probe *request, struct timeval sent_timestamp);

void erase_reference_to_node(t_probe **head, t_probe **tail, t_probe *node,
							 u16 *nb_probe);

t_probe *get_our_probe_request(t_probe **head, t_probe **tail, u16 source_port,
							   struct in_addr ip_src, t_scan_type scan_type,
							   u16 *nb_probes);

bool probe_in_queue(const t_probe *head, u16 port, t_scan_type type,
					struct in_addr ip);
#endif
