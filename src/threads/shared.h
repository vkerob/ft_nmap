#ifndef SHARED_H
#define SHARED_H

#include "parsing.h"
#include "request.h"
#include "scan.h"

#include <pcap/pcap.h>

typedef struct s_probe_queue
{
	t_probe		   *head;
	t_probe		   *tail;
	pthread_mutex_t mut;
	u16				nb_probe;
} t_probe_queue;


typedef struct s_shared_data_sender
{
	_Atomic u16 id;
	_Atomic u16 base_seq;
	size_t		iface_count;
	u16			port_count;

	t_probe_queue to_send;

	// one for each interface
	t_probe_queue  *sent;
	t_program_info *program_info;
	u8				flags;
} t_shared_data_sender;


typedef struct s_receiver_data
{
	pcap_t *handle;

	t_iface_info *iface_info;
	// reference of sent request list of corresponding interface
	t_probe_queue *to_send;
	// reference of sent request list
	t_probe_queue *sent;

	u8				flags;
	t_program_info *program_info;

} t_receiver_data;

bool initialize_shared_data_probe(t_shared_data_sender *shared_data_probe,
								  t_ctx				   *ctx);

bool initialize_receiver_data(t_receiver_data **pcap_ctxs, size_t iface_count,
							  t_shared_data_sender *shared_data_probe,
							  t_iface_info		   *ifaces,
							  t_program_info	   *program_info);

void deinitialize_shared_data(t_shared_data_sender *shared_data_probe,
							  t_ctx				   *ctx);

bool initialize_and_launch_threads(t_ctx *ctx, pthread_t **pcap_threads,
								   pthread_t		   **send_threads,
								   t_shared_data_sender *shared_data_probe,
								   t_receiver_data		*pcap_ctxs);

void join_and_free_threads(pthread_t **pcap_threads, pthread_t **send_threads,
						   u8 nb_send_threads, size_t nb_pcap_threads);

bool initialize_to_send_queue(t_ctx *ctx, t_probe_queue *to_send);

#endif
