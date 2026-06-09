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
#include <stdio.h>
#include <errno.h>
#include <string.h>

sig_atomic_t volatile g_stop = 0;

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

bool substr(char *str, int start, int end, char **ptr)
{
	int	  len = end - start;

	*ptr = calloc(len + 1, sizeof(char));
	if (*ptr == NULL)
	{
		fprintf(stderr, "%s\n", strerror(errno));
		return true;
	}
	strncpy(*ptr, str + start, len);
	return false;
}

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
#include <regex.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>



static bool resolve_services_name(u16 *ports, u16 port_count,
								 t_port_svc_lst *(*head)[MAX_PROTO_COUNT], bool udp_scan, bool tcp_scan)
{
	FILE *fp;
	PCRE2_SIZE error_offset;
	pcre2_code *re = NULL;
	char pattern[512] = { 0 };
	int error_number;
	t_port_svc_lst **tcp_svc_head = head[TCP_INDEX];
	t_port_svc_lst **udp_svc_head = head[UDP_INDEX];


	// Open file in read mode
	fp = fopen("./nmap-services", "r");
	if (fp == NULL) {
			return true;
	}
	snprintf(pattern, sizeof(pattern),
	"([a-z]+)/(%s)	([0-9]+).*$\n", udp_scan && tcp_scan ? "tcp|udp" : (udp_scan ? "udp" : "tcp"));

	re = pcre2_compile(
		(unsigned char *)pattern,               /* the pattern */
		PCRE2_EXTENDED | PCRE2_NEWLINE_ANY | PCRE2_ZERO_TERMINATED, /* indicates pattern is zero-terminated */
		0,                     /* default options */
		&error_number,         /* for error number */
		&error_offset,         /* for error offset */
		NULL);   

	if (re == NULL)
	{
		fprintf(stderr, "Invalid pattern: %s\n", pattern);
		return true;
	}

	int rc;

	char buffer[256];
	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		pcre2_match_data *match_data =
		pcre2_match_data_create_from_pattern(re, NULL);
		rc = pcre2_match(
			re,
			(unsigned char *)buffer,
			strlen(buffer),
			0,
			0,
			match_data,
			NULL);
		if (rc == PCRE2_ERROR_NOMATCH)
		{
						memset(buffer, 0, sizeof(buffer));
			continue ;
		}
		else if (rc < 0)
		{
			fprintf(stderr, "Matching error\n");
			break ;
		}
		else
		{
			PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
			if (ovector == NULL)
			{
				fprintf(stderr, "%s\n", strerror(errno));
				pcre2_match_data_free(match_data);   /* Free resources */
				return true;
			}

			t_port *new = calloc(1, sizeof(t_port));
			if (new == NULL)
			{
				fprintf(stderr, "%s\n", strerror(errno));
				pcre2_match_data_free(match_data);   /* Free resources */
				return true;
			}
			char	*protocol;
			char *port;
			char *service;

			if (substr(buffer, ovector[2], ovector[3], &service) ||
				substr(buffer, ovector[4], ovector[5], &protocol) ||
				substr(buffer, ovector[6], ovector[7], &port))
			{
				pcre2_match_data_free(match_data);   /* Free resources */
				return true;
			}
			
			int port_nb = atoi(port);
			for (int i = 0; i < port_count; i++)
			{
				if (port_nb == ports[i])
				{
					// printf("port %s service: %s\n", port, service);
					t_port_svc_lst *new = calloc(1, sizeof(t_port_svc_lst));
					if (new == NULL)
					{
						//TODO: handle error
						return true;
					}
					else
					{
						new->port = ports[i];
						new->name = service;
						bool tcp_svc_port = (strcmp(protocol, "tcp") == 0);
						bool udp_svc_port = (strcmp(protocol, "udp") == 0);
						if (tcp_svc_port && *tcp_svc_head == NULL)
						{
							*tcp_svc_head = new;
						}
						else if (udp_svc_port && *udp_svc_head == NULL)
						{
							*udp_svc_head = new;
						}
						else
						{
							t_port_svc_lst *tmp;
							tmp = tcp_svc_port ?  *tcp_svc_head : *udp_svc_head;
							while (tmp->next)
							{
								tmp = tmp->next;
							}
							tmp->next = new;
						}
					}
					break;
				}
			}
			memset(buffer, 0, sizeof(buffer));
		}
		pcre2_match_data_free(match_data);   /* Free resources */
	}
	// Close the file
	fclose(fp);
	return false;
}

static void set_scan_presence(t_args *args)
{
	for (u8 i = 0; i < args->nb_scan_types; i++)
	{
		args->udp_scan |= (args->scan_types[i] == SCAN_UDP);
		args->tcp_scan |= (args->scan_types[i] != SCAN_UDP);
	}
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

	if (resolve_services_name(ctx->args.ports, ctx->args.port_count,
		&ctx->port_svc_lst, ctx->args.udp_scan, ctx->args.tcp_scan))
	{
		//TODO: use /etc/services instead
	}

	print_debug_services_lst(ctx->port_svc_lst);

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
	char		 date_buf[64];
	const time_t t = ctx.program_info.start.tv_sec;
	strftime(date_buf, sizeof(date_buf), "%Y-%m-%d %H:%M %z", localtime(&t));
	printf("Starting ft_nmap at %s\n", date_buf);

	if (nmap_main(&ctx))
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
