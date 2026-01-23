#include "ft_nmap.h"

sig_atomic_t volatile g_stop = 0;

void print_parsing_args(t_ctx ctx)
{
	printf("Targets:\n");
	for (size_t i = 0; i < ctx.target_count; i++)
	{
		printf("  %s (%s)\n", ctx.targets[i].input, ctx.targets[i].ip);
	}

	printf("Ports:\n");
	for (size_t i = 0; i < ctx.args.port_count; i++)
	{
		printf("  %u\n", ctx.args.ports[i]);
	}

	printf("Scan type: %u\n", ctx.args.scan_type);
	printf("Speed: %u\n", ctx.args.speed);
	printf("Using device: %s\n", ctx.dev_name);
}

int main(int argc, char **argv)
{
	// if (geteuid() != 0)
	// {
	// 	fprintf(stderr, "ft_nmap: You must be root to run this program.\n");
	// 	return 1;
	// }

	char **targets_input = NULL;
	t_args args;

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

	if (pcap_select_interface(&ctx.dev_name, &ctx.my_ip))
	{
		free_targets(&ctx.targets, ctx.target_count);
		if (ctx.dev_name)
			free(ctx.dev_name);
		return 1;
	}
	print_parsing_args(ctx);

	if (run_scan(&ctx))
	{
		free_targets(&ctx.targets, ctx.target_count);
		free(ctx.dev_name);
		return 1;
	}

	

	free(ctx.dev_name);
	free_targets(&ctx.targets, ctx.target_count);
	return EXIT_SUCCESS;
}
