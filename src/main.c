#include "args.h"
#include "my_signal.h"
#include "scan.h"
#include "parsing.h"
#include "probe_request.h"
#include "shared.h"
#include "capture.h"
#include "commons.h"
#include "capture.h"
#include "send.h"
#include "setup.h"
#include "debug.h"

#include <pcap/pcap.h>
#include <pthread.h>
#include <stdlib.h>

sig_atomic_t volatile g_stop = 0;


bool nmap_main(t_ctx *ctx, pcap_t **handles)
{
	t_shared_data	shared_data;

	if (HAS(ctx->args.flags, F_SPOOF))
	{
		printf(ANSI_BOLD ANSI_COLOR_YELLOW
			   "[*] Spoofing enabled (bonus feature)\n" ANSI_COLOR_RESET);
	}

	initialize_shared_data(&shared_data, handles, ctx);
	initial_probe_requests(
						ctx->targets,
						ctx->target_count,
						ctx->args.ports,
						ctx->args.port_count,
						ctx->args.scan_types,
						ctx->args.nb_scan_types,
						&shared_data.request_list_head,
						&shared_data.request_list_tail);

	shared_data.nb_probe_requests = ctx->args.port_count * ctx->target_count * ctx->args.nb_scan_types;

	pthread_t *pcap_thread = calloc(ctx->iface_count, sizeof(pthread_t));
	if (pcap_thread == NULL)
	{
		return true;
	}
	pthread_t *send_thread = calloc(1, sizeof(pthread_t));
	if (send_thread == NULL)
	{
		return true;
	}
	shared_data.pending_request_head = calloc(ctx->ifacecount, sizeof(t_probe_request *));
	if (shared_data.pending_request_head == NULL)
	{
		return true;
	}
	shared_data.pending_request_tail = calloc(ctx->ifacecount, sizeof(t_probe_request *));
	if (shared_data.pending_request_tail == NULL)
	{
		return true;
	}

	// launch thread to handle captured packets
	for (size_t i = 0; i < ctx->iface_count; i++)
		pthread_create(&pcap_thread[i], NULL, receive_routine, &shared_data);

	// launch thread to send packets
	for (size_t i = 0; i < ctx->iface_count; i++)
		pthread_create(&send_thread[i], NULL, send_routine, &shared_data);

	for (size_t i = 0; i < ctx->iface_count; i++)
		pthread_join(pcap_thread[i], NULL);

	for (size_t i = 0; i < ctx->iface_count; i++)
		pthread_join(send_thread[i], NULL);

	for (size_t i = 0; i < ctx->iface_count; i++)
		pthread_mutex_destroy(&shared_data.mutex);

	free(pcap_thread);
	free(send_thread);

	for (size_t i = 0; i < ctx->iface_count; i++)
		pcap_close(handles[i]);

	return false;
}

int main(int argc, char **argv)
{
	// if (geteuid() != 0)
	// {
	// 	fprintf(stderr, "ft_nmap: You must be root to run this program.\n");
	// 	return 1;
	// }

	char				**targets_input = NULL;
	size_t			target_count = 0;
	t_args			args = { 0 };
	t_port_list	port_list = { 0 };
	t_ctx				ctx = { 0 };


	if (parse_args(argc, argv, &args, &targets_input, &target_count))
	{
		free_tabp((void ***)&targets_input, target_count);
		return EXIT_FAILURE;
	}

	ctx.target_count = target_count;
	ctx.args = args;

	if (resolve_targets(targets_input, ctx.target_count, &ctx.targets))
	{
		free_tabp((void ***)&targets_input, ctx.target_count);
		return EXIT_FAILURE;
	}

	free_tabp((void ***)&targets_input, ctx.target_count);
	if (setup_signal_handlers())
	{
		free_targets(&ctx.targets, ctx.target_count);
		return EXIT_FAILURE;
	}

	if (get_iface_info(&ctx.iface_names, &ctx.iface_count, ctx.targets,
					   ctx.target_count))
	{
		free_targets(&ctx.targets, ctx.target_count);
		return EXIT_FAILURE;
	}

	print_debug_parsing_args(ctx);
	print_debug_iface_info(ctx.iface_names, ctx.iface_count);

	pcap_t	**handles = malloc(sizeof(pcap_t *) * ctx.iface_count);

	if (handles == NULL)
	{
		free_targets(&ctx.targets, ctx.target_count);
		free(ctx.iface_names);
		return EXIT_FAILURE;
	}

	if (setup_pcap_handles(handles, ctx.iface_count, ctx.iface_names))
	{
		free_targets(&ctx.targets, ctx.target_count);
		free(ctx.iface_names);
		return EXIT_FAILURE;
	}

	// if (run_scan(&ctx, handles))
	// {
	// 	free_targets(&ctx.targets, ctx.target_count);
	// 	free(ctx.iface_names);
	// 	return 1;
	// }

	// free(ctx.iface_names);
	// free_targets(&ctx.targets, ctx.target_count);
	if (init_portlist(
		&port_list,
	
		args.port_count,
		args.ports,
		args.nb_scan_types,
		args.scan_types) == false)
	{
		free(ctx.iface_names);
		free_targets(&ctx.targets, ctx.target_count);
		return EXIT_FAILURE;
	}
	if (nmap_main(&ctx, handles) == false)
	{
		free(ctx.iface_names);
		free_targets(&ctx.targets, ctx.target_count);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
