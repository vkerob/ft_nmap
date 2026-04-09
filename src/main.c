#include "args.h"
#include "commons.h"
#include "debug.h"
#include "my_signal.h"
#include "parsing.h"
#include "scan.h"
#include "shared.h"

#include <pcap/pcap.h>
#include <pthread.h>
#include <stdlib.h>

sig_atomic_t volatile g_stop = 0;

static void print_usage() {
	printf("Usage:\n");
	printf("./ft_nmap [--help] [--ports [NUMBER/RANGED]] --ip IP_ADDRESS [--speedup [NUMBER]] [--scan [TYPE]]\n");
	printf("or\n");
	printf("./ft_nmap [--help] [--ports [NUMBER/RANGED]] --file FILE [--speedup [NUMBER]] [--scan [TYPE]]\n");
	printf("\nSCAN TECHNIQUES: \n");
	printf(" If no scan types are specified all will be run\n");
	printf(" --scan <SYN, ACK, XMAS, NULL, URG, UDP>\n");
	printf(" Ex: --scan SYN --scan SYN,XMAS \n");
	printf("\nPORT SPECIFICATION: \n");
	printf(" The number of port specified cannot exceed 1024\n");
	printf(" --ports <port ranges | port number>\n");
	printf("  Ex: --ports 22-32 --ports 22\n");
	printf("\nIP SPECIFICATION: \n");
	printf(" All ip must be provided in their IPV4 format: \n");
	printf(" --ip <ip address or hostname>\n");
	printf("  Ex: --ip 192.168.100.20 --ip google.com\n");
	printf(" --file <source file containing list of ip>\n");
	printf("\nSCAN SPECIFICATION: \n");
	printf(" --speed <0-250>: Number of threads to make the scan faster\n");
	printf("\nOUTPUT: \n");
	printf(" --packet-trace: Show all packets sent and received\n");
	printf("\nHELP: \n");
	printf(" --help: Display this menu\n");
}

bool nmap_main(t_ctx *ctx)
{
	t_shared_data_sender shared_data_probe;
	pthread_t			*pcap_threads = NULL;
	pthread_t			*send_threads = NULL;

	//if (HAS(ctx->args.flags, F_SPOOF))
	//{
	//	printf(ANSI_BOLD ANSI_COLOR_YELLOW
	//		   "[*] Spoofing enabled (bonus feature)\n" ANSI_COLOR_RESET);
	//}

	if (initialize_shared_data_probe(&shared_data_probe, ctx))
	{
		printf("failed to initialize shared data\n");
		return true;
	}
	t_receiver_data *pcap_ctxs = NULL;

	initialize_receiver_data(&pcap_ctxs, ctx->iface_count, &shared_data_probe,
							 ctx->ifaces, &ctx->program_info);

	if (initialize_to_send_queue(ctx, &shared_data_probe.to_send))
	{
		printf("failed to initialize probe request\n");
		return true;
	}

	ctx->args.speed = (ctx->args.speed > 0) ? ctx->args.speed : 0x01;

	// shared_data_probe.to_send.nb_probe
	// 	= ctx->args.port_count * ctx->target_count * ctx->args.nb_scan_types;

	if (initialize_and_launch_threads(ctx, &pcap_threads, &send_threads,
									  &shared_data_probe, pcap_ctxs))
	{
		return true;
	}

	join_and_free_threads(&pcap_threads, &send_threads, ctx->args.speed,
						  ctx->iface_count);

	for (size_t i = 0; i < ctx->iface_count; i++)
	{
		pcap_close(pcap_ctxs[i].handle);
	}

	print_scan_results(ctx);

	free(pcap_ctxs);

	for (size_t i = 0; i < ctx->target_count; i++)
	{
		free(ctx->targets[i].port_list.port_map);
		free(ctx->targets[i].port_list.port_final_state);
		for (u8 j = 0; j < ctx->args.nb_scan_types; j++)
		{
			const t_scan_type scan_type = ctx->args.scan_types[j];
			free(ctx->targets[i].port_list.port_map_rev[scan_type]);
		}
	}

	

	deinitialize_shared_data(&shared_data_probe, ctx);

	return false;
}

int main(const int argc, char **argv)
{
	// if (geteuid() != 0)
	// {
	// 	fprintf(stderr, "ft_nmap: You must be root to run this program.\n");
	// 	return 1;
	// }

	char **targets_input = NULL;
	t_ctx  ctx = { 0 };

	gettimeofday(&ctx.program_info.start, NULL);

	if (parse_args(argc, argv, &ctx.args, &targets_input, &ctx.target_count))
	{
		free_tabp((void ***)&targets_input, ctx.target_count);
		return EXIT_FAILURE;
	}

	if (HAS(ctx.args.flags, F_HELP)) {
		print_usage();
		return EXIT_SUCCESS;
	}

	if (resolve_targets(targets_input, ctx.target_count, &ctx.targets))
	{
		free_tabp((void ***)&targets_input, ctx.target_count);
		return EXIT_FAILURE;
	}

	if (link_port_list_to_each_target(&ctx))
	{
		free_targets(&ctx.targets, ctx.target_count);
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

	// Header — "Starting ft_nmap at 2026-03-18 08:36 +0100"
	char   date_buf[64];
	const time_t t = ctx.program_info.start.tv_sec;
	strftime(date_buf, sizeof(date_buf), "%Y-%m-%d %H:%M %z", localtime(&t));
	printf("Starting ft_nmap at %s\n", date_buf);

	if (nmap_main(&ctx) == false)
	{
		goto error;
	}

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
