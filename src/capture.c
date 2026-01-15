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
		my_ip = NULL;
		pcap_freealldevs(alldevs);
		return true;
	}

	*dev_name = strdup(chosen->name);

	pcap_freealldevs(alldevs);
	return false;
}

// bool capture_traffic(struct in_addr *my_ip)
// {

// 	return false;
// }