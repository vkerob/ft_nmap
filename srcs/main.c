#include "ft_nmap.h"
#include "libft.h"

// sig_atomic_t volatile g_stop = 0;

int main(int argc, char **argv)
{
	// if (geteuid() != 0)
	// {
	// 	fprintf(stderr, "ft_nmap: You must be root to run this program.\n");
	// 	return 1;
	// }

	char								**targets_input = NULL;
	t_args							args;
	// t_socket						socket;
	char								buffer[4096];
	// struct sockaddr_in	sin;
	// int									port = 0;

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

	// if (setup_signal_handlers())
	// {
	// 	free_targets(&ctx.targets, ctx.target_count);
	// 	return 1;
	// }

	// if (pcap_select_interface(&ctx.dev_name, &ctx.my_ip))
	// {
	// 	free_targets(&ctx.targets, ctx.target_count);
	// 	return 1;
	// }

	struct ip			*ip_hdr = (struct ip *)buffer;
	struct tcphdr	*tcp_hdr = (struct tcphdr *)buffer;

	set_default_headers(buffer);
	for (size_t i = 0; i < ctx.target_count; i++)
	{
		printf("Scan %s\n", ctx.targets[i].input);
		update_ip_header_dst_addr(ip_hdr, ctx.targets[i].addr);
		for (size_t j = 0; j < args.port_count; j++)
		{
			printf("Port number %hu\n", args.ports[j]);
			update_port_tcp(tcp_hdr, args.ports[j]);
			update_ip_checksum(buffer);
		}
	}
	// port = ft_atoi(argv[2]);

	// sin.sin_family = AF_INET;
	// sin.sin_port = htons(port);
	// sin.sin_addr.s_addr = inet_addr(argv[1]);

	// memset(buffer, 0, 4096);
	// if (init_socket(&socket) == EXIT_FAILURE){
	// 	return EXIT_FAILURE;
	// }

// #ifdef DEBUG
// 	printf("Socket initiated with fd %d\n", socket.sfd);
// 	printf("Scan %s on port %d\n", argv[1], port);
// #endif

// 	fill_headers(buffer, argv[1], port);

// 	/* Tell the TCP kernel stack to not insert a IP header */
// 	int on = 1;
// 	if (setsockopt(socket.sfd, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on)) < 0){
// 		fprintf(stderr, "Failed to set IP header %s\n", strerror(errno));
// 		close_socket(&socket);
// 		return EXIT_FAILURE;
// 	}

// 	if (sendto(socket.sfd, buffer, sizeof(struct ip) + sizeof(struct tcphdr), 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)  {
// 		fprintf(stderr, "Failed to send TCP packet %s\n", strerror(errno));
// 		close_socket(&socket);
// 		return EXIT_FAILURE;
// 	}

// 	close_socket(&socket);
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
