#include "args.h"
#include "commons.h"
#include "debug.h"
#include "my_signal.h"
#include "parsing.h"
#include "scan.h"
#include "shared.h"
#include "utils.h"
#include <errno.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
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
	printf(" --scan <SYN, ACK, XMAS, NULL, FIN, UDP>\n");
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

static int init_port_map(t_args *args)
{
	u16 max_port_nb = get_max_port_number(args->ports);

	args->port_map = calloc(max_port_nb + 1, sizeof(int));
	if (args->port_map == NULL)
	{
		LOG("ft_nmap: calloc failed: %s\n", strerror(errno));
		return FAILURE;
	}

	memset(args->port_map, -1, sizeof(int) * (max_port_nb + 1));
	for (u16 j = 0; j < args->port_count; j++)
	{
		args->port_map[args->ports[j]] = j;
	}
	return SUCCESS;
}

static void free_ressources(t_ctx *ctx)
{
	free(ctx->args.port_map);

	free_targets(&ctx->targets, ctx->target_count, ctx->args.nb_scan_types,
				 ctx->args.scan_types);

	free(ctx->ifaces);
}

int nmap_main(t_ctx *ctx)
{
	t_shared_data_sender shared_data_probe;
	pthread_t			*pcap_threads = NULL;
	pthread_t			*send_threads = NULL;
	t_receiver_data		*pcap_ctxs = NULL;

	if (initialize_shared_data_probe(&shared_data_probe, ctx) == FAILURE)
	{
		LOG("failed to initialize shared data\n");
		return FAILURE;
	}

	if (initialize_receiver_data(&pcap_ctxs, ctx->iface_count,
								 &shared_data_probe, ctx->ifaces,
								 &ctx->program_info) == FAILURE)
	{
		deinitialize_shared_data(&shared_data_probe, ctx);
		return FAILURE;
	}

	if (initialize_to_send_queue(ctx, &shared_data_probe.to_send) == FAILURE)
	{
		LOG("failed to initialize probe request\n");
		free(pcap_ctxs);
		deinitialize_shared_data(&shared_data_probe, ctx);
		return FAILURE;
	}

	ctx->args.speed = (ctx->args.speed > 0) ? ctx->args.speed : (u8)0x01;

	if (initialize_and_launch_threads(ctx, &pcap_threads, &send_threads,
									  &shared_data_probe, pcap_ctxs) == FAILURE)
	{
		free(pcap_ctxs);
		deinitialize_shared_data(&shared_data_probe, ctx);
		return FAILURE;
	}

	join_and_free_threads(&pcap_threads, &send_threads, ctx->args.speed,
						  ctx->iface_count);

	for (size_t i = 0; i < ctx->iface_count; i++)
	{
		pcap_close(pcap_ctxs[i].handle);
	}

	print_scan_results(ctx);

	free(pcap_ctxs);

	deinitialize_shared_data(&shared_data_probe, ctx);

	return SUCCESS;
}

static void display_program_header(t_ctx *ctx)
{
	// Header — "Starting ft_nmap at 2026-03-18 08:36 +0100"
	char date_buf[32] = { 0 };

	const time_t t = ctx->program_info.start.tv_sec;
	strftime(date_buf, sizeof(date_buf), "%Y-%m-%d %H:%M %z", localtime(&t));
	sync_printf("Starting ft_nmap at %s\n", date_buf);
}

int main(const int argc, char **argv)
{
	t_ctx ctx = { 0 };

	if (gettimeofday(&ctx.program_info.start, NULL) == -1)
	{
		LOG("ft_nmap: gettimeofday failed: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	if (parse_args(argc, argv, &ctx.args, &ctx.targets_input,
				   &ctx.target_count) == FAILURE)
	{
		goto error;
	}

	if (HAS(ctx.args.flags, F_HELP))
	{
		print_usage();
		goto free_and_return_success;
	}

	set_scan_presence(&ctx.args);

	if (resolve_targets(ctx.targets_input, ctx.target_count, &ctx.targets)
		== FAILURE)
	{
		goto error;
	}

	if (init_port_map(&ctx.args) == FAILURE)
	{
		goto error;
	}

	if (init_port_lists(&ctx) == FAILURE)
	{
		goto error;
	}

	if (setup_signal_handlers() == FAILURE)
	{
		goto error;
	}

	if (get_iface_info(&ctx.ifaces, &ctx.iface_count, ctx.targets,
					   ctx.target_count) == FAILURE)
	{
		goto error;
	}

	display_program_header(&ctx);

	nmap_main(&ctx);

free_and_return_success:
	free_tabp((void ***)&ctx.targets_input, ctx.target_count);
	free_ressources(&ctx);
	return EXIT_SUCCESS;

error:
	free_tabp((void ***)&ctx.targets_input, ctx.target_count);
	free_ressources(&ctx);
	return EXIT_FAILURE;
}
