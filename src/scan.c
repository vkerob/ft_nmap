#include "ft_nmap.h"

int	run_scan(t_ctx ctx, t_socket socket, char *datagram)
{
	struct tcphdr		*tcp_hdr = (struct tcphdr *)(datagram);
	t_ip_pseudo_hdr	ip_pseudo_hdr;

	memset(&ip_pseudo_hdr, 0, sizeof(t_ip_pseudo_hdr));

	set_default_headers(datagram, &ip_pseudo_hdr);

	for (size_t i = 0; i < ctx.target_count; i++)
	{
		ip_pseudo_hdr.ip_dst = ctx.targets[i].addr;
		for (size_t j = 0; j < ctx.args.port_count; j++)
		{
			update_socket(&socket.sin, ctx.targets[i], ctx.args.ports[j]);
			update_port_tcp(tcp_hdr, ctx.args.ports[j]);
			calculate_tcp_checksum(&ip_pseudo_hdr, tcp_hdr);
			if (send_packet(socket, datagram) == EXIT_FAILURE)
			{
				free_targets(&ctx.targets, ctx.target_count);
				return EXIT_FAILURE;
			}
		}
	}

	return EXIT_SUCCESS;
}
