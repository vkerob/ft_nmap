#ifndef SHARED_H
#define SHARED_H

#include "parsing.h"
#include "probe_request.h"
#include "scan.h"
#include "typesdef.h"

#include <pcap/pcap.h>

typedef struct s_shared_data_probe
{
	_Atomic u16 id;
	_Atomic u16 base_seq;
	_Atomic u32 nb_probe_requests;
	u32			nb_probe_requests_initial;
	_Atomic u32 nb_probe_requests_done;
	t_target   *targets;
	size_t		target_count;
	size_t		iface_count;
	u16			port_count;
	pcap_t	   *handle;

	t_probe_request *request_list_head;
	t_probe_request *request_list_tail;
	pthread_mutex_t	 request_list_mut;

	// one for each interface
	t_probe_request **pending_request_head;
	t_probe_request **pending_request_tail;
	pthread_mutex_t	 *pending_request_list_mut;
} t_shared_data_probe;

typedef struct s_shared_data_pcap_thread
{
	pcap_t *handle;

	t_iface_info iface_info;
	_Atomic u32	 nb_probe_requests;
	u32			 nb_probe_requests_initial;
	_Atomic u32	 nb_probe_requests_done;

	t_probe_request *request_list_head;
	t_probe_request *request_list_tail;
	pthread_mutex_t	 request_list_mut;

	t_probe_request *pending_request_head;
	t_probe_request *pending_request_tail;
	pthread_mutex_t	 pending_request_list_mut;

} t_shared_data_pcap_thread;

bool initialize_shared_data_probe(t_shared_data_probe *shared_data_probe,
								  t_ctx				  *ctx);

void initialize_shared_data_pcap(t_shared_data_pcap_thread *shared_data_pcap,
								 t_shared_data_probe	   *shared_data_probe);

void deinitialize_shared_data(t_shared_data_probe *shared_data_probe,
							  pcap_t **handles, t_ctx *ctx);

bool initialize_and_launch_threads(size_t nb_pcap_thread, u8 nb_send_thread,
								   pthread_t				**pcap_threads,
								   pthread_t				**send_threads,
								   t_shared_data_probe		 *shared_data_probe,
								   t_shared_data_pcap_thread *shared_data_pcap,
								   t_iface_info				 *ifaces);

void join_and_free_threads(pthread_t **pcap_threads, pthread_t **send_threads,
						   u8 nb_send_threads, size_t nb_pcap_threads);

#endif
