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

// static void print_resume(t_ctx *ctx)
// {
// 	for (size_t i = 0; i < ctx->target_count; i++)
// 	{
// 		printf("%s\n", ctx->targets[i].ip);
// 		for (u16 j = 0; j < ctx->args.port_count; j++)
// 		{
// 			printf("%d: %s", ctx->targets[i].port_state[j].port_nb, ctx->targets[i].port_state[j].close ? "closed" : "open");
// 		}
// 	}
// }
//
bool nmap_main(t_ctx *ctx)
{
	pcap_t				*handle;
	char					errbuf[PCAP_ERRBUF_SIZE];
	const char		*dev_name = ctx->dev_name;
	t_target			first_target = ctx->targets[0];
	pthread_t			pcap_thread;
	pthread_t			send_thread;
	t_shared_data	shared_data;

	if (HAS(ctx->args.flags, F_SPOOF))
	{
		printf(ANSI_BOLD ANSI_COLOR_YELLOW
			   "[*] Spoofing enabled (bonus feature)\n" ANSI_COLOR_RESET);
		// get gateway MAC address for ethernet header, arp request if needed
	}

	if (pcap_setup(&handle, dev_name, ctx->source_ip, errbuf, first_target))
		return true;

	initialize_shared_data(&shared_data, handle, ctx);
	initial_probe_requests(
						ctx->targets,
						ctx->target_count,
						ctx->args.ports,
						ctx->args.port_count,
						ctx->args.scan_types,
						ctx->args.nb_scan_types,
						&shared_data.request_list_head,
						&shared_data.request_list_tail);

	shared_data.nb_probe_requests = ctx->args.port_count * ctx->target_count;
	// launch thread to handle captured packets

	pthread_create(&pcap_thread, NULL, receive_routine, &shared_data);

	// launch thread to send packets
	pthread_create(&send_thread, NULL, send_routine, &shared_data);

	pthread_join(pcap_thread, NULL);

	pthread_join(send_thread, NULL);

	// free_requests_list(&shared_data.request_list_head);
	pthread_mutex_destroy(&shared_data.mutex);
	pcap_close(handle);

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

	ctx.target_count = target_count;
	ctx.args = args;

	if (parse_args(argc, argv, &args, &targets_input, &target_count))
	{
		free_tabp((void ***)&targets_input, target_count);
		return EXIT_FAILURE;
	}

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

	if (pcap_select_interface(&ctx.dev_name, ctx.source_ip))
	{
		free_targets(&ctx.targets, ctx.target_count);
		if (ctx.dev_name)
			free(ctx.dev_name);
		return EXIT_FAILURE;
	}

	print_debug_parsing_args(ctx);


	if (init_portlist(
		&port_list,
		args.port_count,
		args.ports,
		args.nb_scan_types,
		args.scan_types) == false)
	{
		free(ctx.dev_name);
		free_targets(&ctx.targets, ctx.target_count);
		return EXIT_FAILURE;
	}
	if (nmap_main(&ctx) == false)
	{
		free(ctx.dev_name);
		free_targets(&ctx.targets, ctx.target_count);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
