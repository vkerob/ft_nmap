#include "ft_nmap.h"
#include <pcap/pcap.h>
#include <stdbool.h>
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
	free(*dev_name);
	*dev_name = strdup("enp42s0"); // hardcoded for testing purpose

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
	printf("timeout ms: %d\n", timeout_ms);
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

bool pcap_setup(pcap_t **handle, const char *dev_name, struct in_addr my_ip,
				char *errbuf)
{
	*handle = pcap_create(dev_name, errbuf);
	if (!*handle)
	{
		fprintf(stderr, "ft_nmap: pcap_create failed: %s\n", errbuf);
		return true;
	}
	// Configure the handle
	if (pcap_configure(*handle, 65535, 0, 1000, 4 * 1024 * 1024, true,
					   PCAP_D_IN))
	{
		pcap_close(*handle);
		return true;
	}
	// Activate the handle
	int rc = pcap_activate(*handle);
	if (rc < 0)
	{
		fprintf(stderr, "ft_nmap: pcap_activate failed: %s\n",
				pcap_geterr(*handle));
		pcap_close(*handle);
		return true;
	}
	else if (rc > 0)
	{
		fprintf(stderr, "ft_nmap: pcap_activate warning: %s\n",
				pcap_geterr(*handle));
	}

	// Apply a filter to capture only packets destined to my_ip
	char ipbuf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &my_ip, ipbuf, sizeof(ipbuf));
	char filter_expr[128];
	snprintf(filter_expr, sizeof(filter_expr),
			 "tcp and src host 192.168.1.202");

	if (pcap_apply_filter(*handle, filter_expr))
	{
		printf("failed\n");
		pcap_close(*handle);
		return true;
	}

	return false;
}
