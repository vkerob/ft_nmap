#include "setup.h"

#include <ifaddrs.h>
#include <pcap/pcap.h>
#include <stdbool.h>

#define PCAP_SNAPLEN 1024
#define PCAP_PROMISC 0
#define PCAP_BUFFER_SIZE (4 * 1024 * 1024) // 4MB
#define PCAP_IMMEDIATE_MODE true

static bool pcap_configure(pcap_t *handle, int snaplen, int promisc,
						   int buffer_size_bytes, bool immediate_mode)
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

bool pcap_setup(pcap_t **handle, const char *iface_name, char *errbuf)
{
	*handle = pcap_create(iface_name, errbuf);
	if (!*handle)
	{
		fprintf(stderr, "ft_nmap: pcap_create failed: %s\n", errbuf);
		return true;
	}
	// Configure the handle
	if (pcap_configure(*handle, PCAP_SNAPLEN, PCAP_PROMISC, PCAP_BUFFER_SIZE,
					   PCAP_IMMEDIATE_MODE))
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

	char filter_expr[128];

	snprintf(filter_expr, sizeof(filter_expr), "tcp or udp or icmp");

	if (pcap_apply_filter(*handle, filter_expr))
	{
		printf("failed\n");
		pcap_close(*handle);
		return true;
	}

	return false;
}
