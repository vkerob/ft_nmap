#include "ft_nmap.h"

void read_packets(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	(void)user;
	printf("received a packet with len: %d\n", h->len);
	for (size_t i = 0; i < h->len; i++){
		printf("%2x", bytes[i]);
	}
	printf("\n");
	struct ip	ip_hdr;
	
	decode_ip_packet((uint8_t *)&bytes[14], &ip_hdr);
	t_ethernet_hdr	eth_hdr;
	decode_ethernet_packet((uint8_t *)bytes, &eth_hdr);
	print_ip_header(&ip_hdr);
	print_eth_header(&eth_hdr);
	fflush(stdout);
}

int	run_scan(t_ctx ctx, t_socket socket, char *datagram)
{
	struct tcphdr		*tcp_hdr = (struct tcphdr *)(datagram);
	t_ip_pseudo_hdr	ip_pseudo_hdr;

	memset(&ip_pseudo_hdr, 0, sizeof(t_ip_pseudo_hdr));

	char			errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t	*alldevsp = NULL;
	if (pcap_findalldevs(&alldevsp, errbuf) < 0)
	{
		fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
		return EXIT_FAILURE;
	}

	// pcap_if_t *tmp = alldevsp;


	// while (tmp)
	// {
	// 	printf("Name: %s\n", tmp->name);
	// 	tmp = tmp->next;
	// }

	pcap_t *capture = pcap_open_live("bridge100", 262144, 0, 1, errbuf);
	if (capture == NULL)
	{
		fprintf(stderr, "pcap_open_live: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}
	if (set_pcap_filter(capture) == EXIT_FAILURE)
	{
		return EXIT_FAILURE;
	}

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

	int nb_packets_recv = pcap_loop(capture, 2, read_packets, NULL);
	(void)nb_packets_recv;
	// printf("Number of packets received: %d\n", nb_packets_recv);

	pcap_close(capture);
	return EXIT_SUCCESS;
}
