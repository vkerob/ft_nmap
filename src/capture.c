#include "compat_pcap.h"
#include "ft_nmap.h"
#include <string.h>

static bool has_ipv4_addr(const pcap_if_t *dev, struct in_addr *my_ip)
{
	for (pcap_addr_t *addr = dev->addresses; addr; addr = addr->next)
	{
		// if it's an IPv4 address we can cast into sockaddr_in for sin_addr
		if (addr->addr && addr->addr->sa_family == AF_INET)
		{
			const struct sockaddr_in *sin
				= (const struct sockaddr_in *)addr->addr;
			*my_ip = sin->sin_addr;
			return true;
		}
	}
	return false;
}

static const pcap_if_t *pick_default_dev(const pcap_if_t *alldevs,
										 struct in_addr	 *my_ip)
{
	for (const pcap_if_t *dev = alldevs; dev; dev = dev->next)
	{
		// skip loopback
		if (dev->flags & PCAP_IF_LOOPBACK)
			continue;

		if (has_ipv4_addr(dev, my_ip))
			return dev;
	}
	return NULL;
}

bool pcap_select_interface(char **dev_name, struct in_addr *my_ip)
{
	char	   errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs = NULL;

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "ft_nmap: pcap_findalldevs failed: %s\n", errbuf);
		return true;
	}

	const pcap_if_t *chosen = pick_default_dev(alldevs, my_ip);
	if (!chosen)
	{
		fprintf(stderr, "ft_nmap: no suitable network interface found\n");
		pcap_freealldevs(alldevs);
		return true;
	}

	*dev_name = strdup(chosen->name);
	if (!*dev_name)
	{
		fprintf(stderr, "ft_nmap: strdup failed\n");
		pcap_freealldevs(alldevs);
		return true;
	}

	pcap_freealldevs(alldevs);
	return false;
}

bool pcap_configure(pcap_t *handle, int snaplen, int promisc, int timeout_ms,
					int buffer_size_bytes, bool immediate_mode, int direction)
{
	if (pcap_set_snaplen(handle, snaplen) != 0)
	{
		fprintf(stderr, "ft_nmap: pcap_set_snaplen failed\n");
		return true;
	}
	if (pcap_set_promisc(handle, promisc) != 0)
	{
		fprintf(stderr, "ft_nmap: pcap_set_promisc failed\n");
		return true;
	}
	if (pcap_set_timeout(handle, timeout_ms) != 0)
	{
		fprintf(stderr, "ft_nmap: pcap_set_timeout failed\n");
		return true;
	}
	if (pcap_set_buffer_size(handle, buffer_size_bytes) != 0)
	{
		fprintf(stderr, "ft_nmap: pcap_set_buffer_size failed\n");
		return true;
	}
	if (pcap_set_immediate_mode(handle, immediate_mode) != 0)
	{
		fprintf(stderr, "ft_nmap: pcap_set_immediate_mode failed\n");
		return true;
	}
	(void)direction;
	// if (pcap_setdirection(handle, direction) != 0)
	// {
	// 	fprintf(stderr, "ft_nmap: pcap_setdirection failed\n");
	// 	return true;
	// }
	return false;
}

static bool pcap_apply_filter(pcap_t *handle, const char *filter_expr)
{
	struct bpf_program fp;
	if (pcap_compile(handle, &fp, filter_expr, 1, PCAP_NETMASK_UNKNOWN) == -1)
	{
		fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(handle));
		return true;
	}
	if (pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(handle));
		pcap_freecode(&fp);
		return true;
	}
	pcap_freecode(&fp);
	return false;
}

t_target *find_corresponding_target(
	struct ip *ip_hdr, t_target *targets, size_t target_count
)
{
	for (size_t i = 0; i < target_count; i++)
	{
		printf("decoded: %d target: %d\n", ip_hdr->ip_src.s_addr, targets[i].addr.s_addr);
		if (ip_hdr->ip_src.s_addr == targets[i].addr.s_addr)
		{
			printf("%s host responded\n", targets->ip);
			return &targets[i];
		}
	}
	printf("target not found\n");
	return NULL;
}

bool handle_captured_packet(pcap_t *handle, t_target *targets, size_t target_count)
{
	while (!g_stop)
	{
		struct pcap_pkthdr *hdr;
		const u_char	   *pkt;
		int					rc = pcap_next_ex(handle, &hdr, &pkt);

		if (rc == 0)
			continue; // timeout
		if (rc == -1)
		{ // error
			fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(handle));
			break;
		}
		if (rc == -2)
			break; // EOF offline

		t_ethernet_hdr	eth_hdr;
		struct ip				ip_hdr;
		struct tcphdr		tcp_hdr;

		decode_datagram((uint8_t *)pkt, &eth_hdr, &ip_hdr, &tcp_hdr);

		print_headers(&eth_hdr, &ip_hdr, &tcp_hdr);

		fflush(stdout);
		(void)target_count;
		(void)targets;
		// t_target *target = find_corresponding_target(&ip_hdr, targets, target_count);
		// (void)target;
		// pkt = NULL;
		// printf("Captured packet of length %u\n", hdr->len);
		break ;
	}
	pcap_close(handle);
	return false;
}

bool	capture_traffic(t_ctx *ctx, t_socket *socket, char *datagram)
{
	pcap_t *handle;
	char	errbuf[PCAP_ERRBUF_SIZE];
	const char *dev_name = ctx->dev_name;
	struct in_addr my_ip = ctx->my_ip;
	t_target *targets = ctx->targets;
size_t target_count = ctx->target_count;

	handle = pcap_create(dev_name, errbuf);
	if (!handle)
	{
		fprintf(stderr, "ft_nmap: pcap_create failed: %s\n", errbuf);
		return true;
	}
	if (pcap_configure(handle, 65535, 0, 100, 4 * 1024 * 1024, true, PCAP_D_IN))
	{
		pcap_close(handle);
		return true;
	}
	int rc = pcap_activate(handle);
	if (rc < 0)
	{
		fprintf(stderr, "ft_nmap: pcap_activate failed: %s\n",
				pcap_geterr(handle));
		pcap_close(handle);
		return true;
	}
	else if (rc > 0)
	{
		fprintf(stderr, "ft_nmap: pcap_activate warning: %s\n",
				pcap_geterr(handle));
	}
	// Apply a filter to capture only packets destined to my_ip
	char ipbuf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &my_ip, ipbuf, sizeof(ipbuf));

	char filter_expr[128];
	snprintf(filter_expr, sizeof(filter_expr), "tcp and src host 192.168.64.11");

	if (pcap_apply_filter(handle, filter_expr))
	{
		printf("failed\n");
		pcap_close(handle);
		return true;
	}

	run_scan(*ctx, *socket, datagram);
	if (handle_captured_packet(handle, targets, target_count))
		return true;

	return false;
}
