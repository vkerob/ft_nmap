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
	printf("--os-detect: Enable OS detection\n");
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
	printf("max port: %u\n", max_port_nb);
	args->port_map = calloc(max_port_nb, sizeof(int));
	if (args->port_map == NULL)
	{
		LOG("ft_nmap: ft_calloc: %s\n", strerror(errno));
		return true;
	}
	memset(args->port_map, -1, max_port_nb * sizeof(int));
	for (u16 j = 0; j < args->port_count; j++)
	{
		args->port_map[args->ports[j]] = j;
	}
	return false;
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
		LOG("failed to initialize the port map\n");
		return true;
	}

	if (resolve_services_name(ctx->args.port_count, ctx->args.port_map,
		&ctx->port_svc, ctx->args.udp_scan, ctx->args.tcp_scan))
	{
		LOG("failed to resolve services\n");
		return true;
	}

	print_debug_services(ctx->port_svc, ctx->args.port_count);

	ctx->args.speed = (ctx->args.speed > 0) ? ctx->args.speed : 0x01;

	/* set_scan_presence is now invoked from main() before init_portlist;
	 * keeping it here would be redundant. */
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
		if (ctx->args.tcp_scan)
		{
			free(ctx->targets[i].port_list.port_final_state[TCP_INDEX]);
		}
		if (ctx->args.udp_scan)
		{
			free(ctx->targets[i].port_list.port_final_state[UDP_INDEX]);
		}
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
		free_tabp((void ***)&targets_input, ctx.target_count);
		return EXIT_FAILURE;
	}

	if (init_port_lists(&ctx))
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
	char		 date_buf[64];
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
	if (ctx.port_svc[TCP_INDEX] || ctx.port_svc[UDP_INDEX])
	{
		free_services(ctx.port_svc);
	}
	free_targets(&ctx.targets, ctx.target_count);
	return EXIT_FAILURE;
}
