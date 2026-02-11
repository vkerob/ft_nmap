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

bool nmap_main(t_ctx *ctx, pcap_t **handles)
{
	t_shared_data shared_data;
	pthread_t	 *pcap_threads = NULL;
	pthread_t	 *send_threads = NULL;

	if (HAS(ctx->args.flags, F_SPOOF))
	{
		printf(ANSI_BOLD ANSI_COLOR_YELLOW
			   "[*] Spoofing enabled (bonus feature)\n" ANSI_COLOR_RESET);
	}

	if (initialize_shared_data(&shared_data, handles, ctx))
	{
		return true;
	}

	initial_probe_requests(ctx, &shared_data.request_list_head,
						   &shared_data.request_list_tail);

	return true;
	shared_data.nb_probe_requests
		= ctx->args.port_count * ctx->target_count * ctx->args.nb_scan_types;

	if (initialize_and_launch_threads(ctx->iface_count, ctx->args.speed,
									  &pcap_threads, &send_threads,
									  &shared_data)
		== false)
	{
		return true;
	}

	join_and_free_threads(pcap_threads, send_threads, ctx->args.speed,
						  ctx->iface_count);

	deinitialize_shared_data(&shared_data, handles, ctx);

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

	pcap_t **handles = malloc(sizeof(pcap_t *) * ctx.iface_count);

	if (handles == NULL)
	{
		goto error;
	}

	if (setup_pcap_handles(handles, ctx.iface_count, ctx.iface_names))
	{
		goto error;
	}

	// if (init_portlist(&port_list, args.port_count, args.ports,
	// 				  args.nb_scan_types, args.scan_types)
	// 	== false)
	// {
	// 	goto error;
	// }
	if (nmap_main(&ctx, handles) == false)
	{
		goto error;
	}

	free(handles);
	free(ctx.iface_names);
	free_targets(&ctx.targets, ctx.target_count);
	return EXIT_SUCCESS;

error:
	free(ctx.iface_names);
	free_targets(&ctx.targets, ctx.target_count);
	return EXIT_FAILURE;
}
