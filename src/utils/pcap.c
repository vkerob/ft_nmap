#include "capture.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define PCAP_SNAPLEN 1024
#define PCAP_PROMISC 0
#define PCAP_BUFFER_SIZE (4 * 1024 * 1024) // 4MB
#define PCAP_IMMEDIATE_MODE true

static bool pcap_configure(pcap_t *handle, int snaplen, int promisc,
						   int buffer_size_bytes, bool immediate_mode)
{
	if (pcap_set_snaplen(handle, snaplen) != 0)
	{
		LOG("ft_nmap: pcap_set_snaplen failed\n");
		return true;
	}
	if (pcap_set_promisc(handle, promisc) != 0)
	{
		LOG("ft_nmap: pcap_set_promisc failed\n");
		return true;
	}
	if (pcap_set_buffer_size(handle, buffer_size_bytes) != 0)
	{
		LOG("ft_nmap: pcap_set_buffer_size failed\n");
		return true;
	}
	if (pcap_set_immediate_mode(handle, immediate_mode) != 0)
	{
		LOG("ft_nmap: pcap_set_immediate_mode failed\n");
		return true;
	}
	return false;
}

static char *build_filter_expr(const char *ip_src_interface, t_target *targets,
							   size_t target_count, int iface_index)
{
	const size_t filter_len = 100 + 30 * target_count;
	char		*filter_expr = malloc(filter_len);
	if (!filter_expr)
	{
		LOG("ft_nmap: malloc failed for filter expression\n");
		return NULL;
	}

	int written
		= snprintf(filter_expr, filter_len,
				   "(tcp or udp or icmp) and dst host %s", ip_src_interface);

	bool first_target = true;
	for (size_t i = 0; i < target_count; i++)
	{
		if (targets[i].iface_info->iface_index != iface_index)
			continue;

		char ip_buf[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &targets[i].addr, ip_buf, sizeof(ip_buf));

		if (first_target)
		{
			written += snprintf(filter_expr + written, filter_len - written,
								" and (src host %s", ip_buf);
			first_target = false;
		}
		else
		{
			written += snprintf(filter_expr + written, filter_len - written,
								" or src host %s", ip_buf);
		}
	}
	if (!first_target)
		snprintf(filter_expr + written, filter_len - written, ")");

	return filter_expr;
}

static bool pcap_apply_filter(pcap_t *handle, const char *filter_expr)
{
	struct bpf_program fp;
	if (pcap_compile(handle, &fp, filter_expr, 1, PCAP_NETMASK_UNKNOWN) == -1)
	{
		LOG("pcap_compile failed: %s\n", pcap_geterr(handle));
		return true;
	}
	if (pcap_setfilter(handle, &fp) == -1)
	{
		LOG("pcap_setfilter failed: %s\n", pcap_geterr(handle));
		pcap_freecode(&fp);
		return true;
	}
	pcap_freecode(&fp);
	return false;
}

bool pcap_setup(t_receiver_data *pcap_ctx, char *errbuf, t_target *targets,
				size_t target_count)
{
	const char *ip_src_interface = inet_ntoa(pcap_ctx->iface_info->ip_addr);
	pcap_ctx->handle = pcap_create(pcap_ctx->iface_info->name, errbuf);
	if (!pcap_ctx->handle)
	{
		LOG("ft_nmap: pcap_create failed: %s\n", errbuf);
		return true;
	}
	// Configure the handle
	if (pcap_configure(pcap_ctx->handle, PCAP_SNAPLEN, PCAP_PROMISC,
					   PCAP_BUFFER_SIZE, PCAP_IMMEDIATE_MODE))
	{
		pcap_close(pcap_ctx->handle);
		return true;
	}
	// Activate the handle
	int rc = pcap_activate(pcap_ctx->handle);
	if (rc < 0)
	{
		LOG("ft_nmap: pcap_activate failed: %s\n",
			pcap_geterr(pcap_ctx->handle));
		pcap_close(pcap_ctx->handle);
		return true;
	}
	else if (rc > 0)
	{
		LOG("ft_nmap: pcap_activate warning: %s\n",
			pcap_geterr(pcap_ctx->handle));
	}

	char *filter_expr
		= build_filter_expr(ip_src_interface, targets, target_count,
							pcap_ctx->iface_info->iface_index);
	if (!filter_expr)
	{
		pcap_close(pcap_ctx->handle);
		return true;
	}

	if (pcap_apply_filter(pcap_ctx->handle, filter_expr))
	{
		LOG("ft_nmap: pcap_apply_filter failed\n");
		free(filter_expr);
		pcap_close(pcap_ctx->handle);
		return true;
	}
	free(filter_expr);
	return false;
}
