#include "args.h"
#include "commons.h"
#include "debug.h"
#include "my_signal.h"
#include "parsing.h"
#include "scan.h"
#include "shared.h"
#include "utils.h"

#include <pcap/pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

sig_atomic_t volatile g_stop = 0;

static void print_usage()
{
	printf("Usage:\n");
	printf("./ft_nmap [--help] [--ports [NUMBER/RANGED]] --ip IP_ADDRESS "
		   "[--speedup [NUMBER]] [--scan [TYPE]]\n");
	printf("or\n");
	printf("./ft_nmap [--help] [--ports [NUMBER/RANGED]] --file FILE "
		   "[--speedup [NUMBER]] [--scan [TYPE]]\n");
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
	printf(" --verbose: No port states are ignored\n");
	printf(" --reason: Show the reason why the port is in that state\n");
	printf("SERVICE/VERSION DETECTION:\n");
	printf(" --version: Probe open ports to determine version info\n");
	printf("OS DETECTION\n");
	printf(" --os-detect: Enable OS detection\n");
	printf("\nDECOY SCAN:\n");
	printf(" --decoy <decoy1,decoy2[,ME],...>: Cloak scan with decoy source "
		   "IPs\n");
	printf("  Ex: --decoy 192.168.1.100,10.0.0.5,ME\n");
	printf("  Max %d decoys\n", MAX_DECOYS);
	printf("\nHELP: \n");
	printf(" --help: Display this menu\n");
}
static void set_scan_presence(t_args *args)
{
	for (u8 i = 0; i < args->nb_scan_types; i++)
	{
		args->udp_scan |= (args->scan_types[i] == SCAN_UDP);
		args->tcp_scan |= (args->scan_types[i] != SCAN_UDP);
	}
}


static bool init_port_map(t_args *args)
{
	u16 max_port_nb = get_max_port_number(args->ports);

	args->port_map = calloc(max_port_nb + 1, sizeof(int));
	if (args->port_map == NULL)
	{
		LOG("ft_nmap: ft_calloc: %s\n", strerror(errno));
		return true;
	}
	for (u16 i = 0; i < max_port_nb; i++)
	{
		args->port_map[i] = -1;
	}
	for (u16 j = 0; j < args->port_count; j++)
	{
		args->port_map[args->ports[j]] = j;
	}
	return false;
}


static void free_ressources(t_ctx *ctx)
{
	better_free(ctx->args.port_map);

	free_services(&ctx->port_svc, ctx->args.port_count);

	free_targets(&ctx->targets, ctx->target_count, ctx->args.port_count, ctx->args.nb_scan_types, ctx->args.scan_types);

	better_free(ctx->ifaces);
}


bool nmap_main(t_ctx *ctx)
{
	t_shared_data_sender shared_data_probe;
	pthread_t			*pcap_threads = NULL;
	pthread_t			*send_threads = NULL;

	// if (HAS(ctx->args.flags, F_SPOOF))
	//{
	//	printf(ANSI_BOLD ANSI_COLOR_YELLOW
	//		   "[*] Spoofing enabled (bonus feature)\n" ANSI_COLOR_RESET);
	// }

	if (initialize_shared_data_probe(&shared_data_probe, ctx))
	{
		LOG("failed to initialize shared data\n");
		return true;
	}
	t_receiver_data *pcap_ctxs = NULL;

	initialize_receiver_data(&pcap_ctxs, ctx->iface_count, &shared_data_probe,
							 ctx->ifaces, &ctx->program_info);

	if (initialize_to_send_queue(ctx, &shared_data_probe.to_send))
	{
		LOG("failed to initialize probe request\n");
		return true;
	}

	if (init_port_map(&ctx->args))
	{
				better_free(pcap_ctxs);
		LOG("failed to initialize the port map\n");
		return true;
	}

	if (resolve_services_name(ctx->args.port_count, ctx->args.port_map,
		&ctx->port_svc, ctx->args.udp_scan, ctx->args.tcp_scan))
	{
				better_free(pcap_ctxs);
		LOG("failed to resolve services\n");
		return true;
	}

	ctx->args.speed = (ctx->args.speed > 0) ? ctx->args.speed : 0x01;

	/* set_scan_presence is now invoked from main() before init_portlist;
	 * keeping it here would be redundant. */
	// shared_data_probe.to_send.nb_probe
	// 	= ctx->args.port_count * ctx->target_count * ctx->args.nb_scan_types;

	if (initialize_and_launch_threads(ctx, &pcap_threads, &send_threads,
									  &shared_data_probe, pcap_ctxs))
	{
		better_free(pcap_ctxs);
		deinitialize_shared_data(&shared_data_probe, ctx);
		return true;
	}

	join_and_free_threads(&pcap_threads, &send_threads, ctx->args.speed,
						  ctx->iface_count);

	for (size_t i = 0; i < ctx->iface_count; i++)
	{
		pcap_close(pcap_ctxs[i].handle);
	}

	print_scan_results(ctx);

	better_free(pcap_ctxs);
	deinitialize_shared_data(&shared_data_probe, ctx);

	return false;
}


int main(const int argc, char **argv)
{
	// if (geteuid() != 0)
	// {
	// 	LOG("ft_nmap: You must be root to run this program.\n");
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

	if (HAS(ctx.args.flags, F_HELP))
	{
		print_usage();
		return EXIT_SUCCESS;
	}

	/* Must run before link_port_list_to_each_target: init_portlist uses
	 * tcp_scan / udp_scan to decide which port_final_state buffers to
	 * allocate, and the "no --scan" default branch in parse_args doesn't
	 * set those flags. */
	set_scan_presence(&ctx.args);

	if (resolve_targets(targets_input, ctx.target_count, &ctx.targets))
	{
		goto error;
	}
	free_tabp((void ***)&targets_input, ctx.target_count);

	if (init_port_lists(&ctx))
	{
		goto error;
	}

	free_tabp((void ***)&targets_input, ctx.target_count);
	if (setup_signal_handlers())
	{
		goto error;
	}

	if (get_iface_info(&ctx.ifaces, &ctx.iface_count, ctx.targets,
					   ctx.target_count))
	{
		goto error;
	}

	// Header — "Starting ft_nmap at 2026-03-18 08:36 +0100"
	char		 date_buf[64];
	const time_t t = ctx.program_info.start.tv_sec;
	strftime(date_buf, sizeof(date_buf), "%Y-%m-%d %H:%M %z", localtime(&t));
	printf("Starting ft_nmap at %s\n", date_buf);

	nmap_main(&ctx);

	free_ressources(&ctx);
	return EXIT_SUCCESS;

error:
	free_ressources(&ctx);
	return EXIT_FAILURE;
}
