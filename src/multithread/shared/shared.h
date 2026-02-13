#ifndef SHARED_H
#define SHARED_H

#include "parsing.h"
#include "request.h"
#include "scan.h"
#include "typesdef.h"

#include <pcap/pcap.h>

typedef struct s_pending_queue
{
	t_request	   *head;
	t_request	   *tail;
	pthread_mutex_t mut;
	u8				nb_pending_requests;
} t_pending_queue;

typedef struct s_request_list
{
	t_request	   *head;
	t_request	   *tail;
	pthread_mutex_t mut;
	u8				nb_probe_requests;
} t_request_list;

typedef struct s_shared_data_probe
{
	_Atomic u16 id;
	_Atomic u16 base_seq;
	size_t		iface_count;
	u16			port_count;

	t_request_list probe_request_list;

	// one for each interface
	t_pending_queue *pending_request_list;
} t_shared_data_probe;

typedef struct s_shared_data_pcap
{
	pcap_t *handle;

	t_iface_info iface_info;

	t_request_list *probe_request_list; // pointer to shared request list

	t_pending_queue *pending_request_list;

} t_shared_data_pcap;

bool initialize_shared_data_probe(t_shared_data_probe *shared_data_probe,
								  t_ctx				  *ctx);

bool initialize_shared_data_pcap(t_shared_data_pcap **pcap_ctxs,
								 size_t				  iface_count,
								 t_shared_data_probe *shared_data_probe,
								 t_iface_info		 *ifaces);

void deinitialize_shared_data(t_shared_data_probe *shared_data_probe,
							  pcap_t **handles, t_ctx *ctx);

bool initialize_and_launch_threads(size_t nb_pcap_thread, u8 nb_send_thread,
								   pthread_t		  **pcap_threads,
								   pthread_t		  **send_threads,
								   t_shared_data_probe *shared_data_probe,
								   t_shared_data_pcap  *shared_data_pcap,
								   t_iface_info		   *ifaces);

void join_and_free_threads(pthread_t **pcap_threads, pthread_t **send_threads,
						   u8 nb_send_threads, size_t nb_pcap_threads);

bool initial_probe_request_list(t_ctx *ctx, t_request_list *probe_request_list);

#endif
