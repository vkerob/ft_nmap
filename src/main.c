#include "ft_nmap.h"

sig_atomic_t volatile g_stop = 0;

int main(int argc, char **argv)
{
	// if (geteuid() != 0)
	// {
	// 	fprintf(stderr, "ft_nmap: You must be root to run this program.\n");
	// 	return 1;
	// }

	char								**targets_input = NULL;
	t_args							args;
	t_socket						socket;
	char								datagram[4096];

	memset(&args, 0, sizeof(args));
	if (parse_args(argc, argv, &args, &targets_input))
	{
		free_tabp((void ***)&targets_input, args.target_count);
		return 1;
	}

	t_ctx ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.target_count = args.target_count;
	ctx.args = args;

	if (resolve_targets(targets_input, args.target_count, &ctx.targets))
	{
		free_tabp((void ***)&targets_input, args.target_count);
		return 1;
	}
	free_tabp((void ***)&targets_input, args.target_count);

	if (setup_signal_handlers())
	{
		free_targets(&ctx.targets, ctx.target_count);
		return 1;
	}

	socket.sin.sin_family = AF_INET;
	init_socket(&socket);


	if (pcap_select_interface(&ctx.dev_name, &ctx.my_ip))
	{
		free_targets(&ctx.targets, ctx.target_count);
		if (ctx.dev_name)
			free(ctx.dev_name);
		return 1;
	}

	ctx.dev_name = strdup("bridge100");
	if (capture_traffic(&ctx, &socket, datagram))
	{
		free_targets(&ctx.targets, ctx.target_count);
		free(ctx.dev_name);
		return 1;
	}

	// for (size_t i = 0; i < ctx.target_count; i++)
	// 	printf("Resolved target %zu: %s (%s)\n", i, ctx.targets[i].input,
	// 		   ctx.targets[i].ip);

	// for (size_t i = 0; i < ctx.args.port_count; i++)
	// 	printf("Port %zu: %u\n", i, ctx.args.ports[i]);

	// printf("Scan type: %u\n", ctx.args.scan_type);
	// printf("Speed: %u\n", ctx.args.speed);

	// printf("Using device: %s\n", ctx.dev_name);

	// free_targets(&ctx.targets, ctx.target_count);
	// free(ctx.dev_name);

	close_socket(socket);
	return EXIT_SUCCESS;

	// if (capture_traffic(&ctx.my_ip) != 0)
	// {
	// 	free_targets(&ctx.targets, ctx.target_count);
	// 	return 1;
	// }

	// for (size_t i = 0; i < ctx.target_count; i++)
	// 	printf("Resolved target %zu: %s (%s)\n", i, ctx.targets[i].input,
	// 		   ctx.targets[i].ip);

	// for (size_t i = 0; i < ctx.args.port_count; i++)
	// 	printf("Port %zu: %u\n", i, ctx.args.ports[i]);

	// printf("Scan type: %u\n", ctx.args.scan_type);
	// printf("Speed: %u\n", ctx.args.speed);

	// printf("Using device: %s\n", ctx.dev_name);

	// free_targets(&ctx.targets, ctx.target_count);
	// return 0;
	// if (init_socket() != 0)
	// 	return 1;

	// if (setup_signal_handlers() != 0)
	// 	goto error;

	// if (run_nmap() != 0)
	// 	goto error;

	// error:
	// 	return 1;
}
