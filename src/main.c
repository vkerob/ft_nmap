#include "ft_nmap.h"

sig_atomic_t volatile g_stop = 0;
int g_pipefd[2];

int main(int argc, char **argv)
{
	// if (geteuid() != 0)
	// {
	// 	fprintf(stderr, "ft_nmap: You must be root to run this program.\n");
	// 	return 1;
	// }

	if (pipe(g_pipefd) == -1)
	{
		perror("pipe");
		return 1;
	}

	char **targets_input = NULL;
	size_t target_count = 0;
	t_args args;

	memset(&args, 0, sizeof(args));
	if (parse_args(argc, argv, &args, &targets_input, &target_count))
	{
		free_tabp((void ***)&targets_input, target_count);
		return 1;
	}

	t_ctx ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.target_count = target_count;
	ctx.args = args;

	if (resolve_targets(targets_input, ctx.target_count, &ctx.targets))
	{
		free_tabp((void ***)&targets_input, ctx.target_count);
		return 1;
	}
	free_tabp((void ***)&targets_input, ctx.target_count);

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
	print_debug_parsing_args(ctx);

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
