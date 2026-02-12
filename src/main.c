#include "args.h"
#include "commons.h"
#include "debug.h"
#include "my_signal.h"
#include "parsing.h"
#include "probe_request.h"
#include "scan.h"
#include "setup.h"
#include "shared.h"

#include <pcap/pcap.h>
#include <pthread.h>
#include <stdlib.h>

sig_atomic_t volatile g_stop = 0;

bool nmap_main(t_ctx *ctx)
{
	t_shared_data			   shared_data;
	t_shared_data_pcap_thread *shared_data_pcap = NULL;
	pthread_t				  *pcap_threads = NULL;
	pthread_t				  *send_threads = NULL;

	if (HAS(ctx->args.flags, F_SPOOF))
	{
		printf(ANSI_BOLD ANSI_COLOR_YELLOW
			   "[*] Spoofing enabled (bonus feature)\n" ANSI_COLOR_RESET);
	}

	if (initialize_shared_data(&shared_data, &shared_data_pcap, ctx))
	{
		printf("failed to initialize shared data\n");
		return true;
	}

	if (initial_probe_requests(ctx, &shared_data.request_list_head,
							   &shared_data.request_list_tail))
	{
		printf("failed to initialize probe request\n");
		return true;
	}

	ctx->args.speed = (ctx->args.speed > 0) ? ctx->args.speed : 0x01;
	shared_data.nb_probe_requests
		= ctx->args.port_count * ctx->target_count * ctx->args.nb_scan_types;

	if (initialize_and_launch_threads(ctx->iface_count, ctx->args.speed,
									  &pcap_threads, &send_threads,
									  &shared_data, &shared_data_pcap))
	{
		return true;
	}

	join_and_free_threads(&pcap_threads, &send_threads, ctx->args.speed,
						  ctx->iface_count);

	// deinitialize_shared_data(&shared_data, handles, ctx);

	return false;
}

int main(int argc, char **argv)
{
	// if (geteuid() != 0)
	// {
	// 	fprintf(stderr, "ft_nmap: You must be root to run this program.\n");
	// 	return 1;
	// }

	char **targets_input = NULL;
	size_t target_count = 0;
	t_args args = { 0 };
	t_ctx  ctx = { 0 };
	// t_iface_info *finfos = NULL;

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

	if (get_iface_info(&ctx.ifaces, &ctx.iface_count, ctx.targets,
					   ctx.target_count))
	{
		free_targets(&ctx.targets, ctx.target_count);
		return EXIT_FAILURE;
	}

	print_debug_parsing_args(ctx);
	print_debug_iface_info(ctx.ifaces, ctx.iface_count);

	// can't declare with sizeof(pcap_t) because structure is not inside the
	// pcap.h
	ctx.handles = calloc(ctx.iface_count, sizeof(pcap_t *));

	if (ctx.handles == NULL)
	{
		goto error;
	}

	if (setup_pcap_handles(ctx.handles, ctx.iface_count, ctx.ifaces))
	{
		goto error;
	}

	// if (init_portlist(&port_list, args.port_count, args.ports,
	// 				  args.nb_scan_types, args.scan_types)
	// 	== false)
	// {
	// 	goto error;
	// }
	if (nmap_main(&ctx))
	{
		goto error;
	}

	free(ctx.handles);
	free(ctx.ifaces);
	free_targets(&ctx.targets, ctx.target_count);
	return EXIT_SUCCESS;

error:
	if (ctx.ifaces)
	{
		free(ctx.ifaces);
	}
	if (ctx.handles)
	{
		free(ctx.handles);
	}
	free_targets(&ctx.targets, ctx.target_count);
	return EXIT_FAILURE;
}
