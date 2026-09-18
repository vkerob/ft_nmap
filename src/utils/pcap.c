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

static int pcap_configure(pcap_t *handle, int snaplen, int promisc,
						  int buffer_size_bytes, bool immediate_mode)
{
	if (pcap_set_snaplen(handle, snaplen) != 0)
	{
		LOG("ft_nmap: pcap_set_snaplen failed\n");
		return FAILURE;
	}
	if (pcap_set_promisc(handle, promisc) != 0)
	{
		LOG("ft_nmap: pcap_set_promisc failed\n");
		return FAILURE;
	}
	if (pcap_set_buffer_size(handle, buffer_size_bytes) != 0)
	{
		LOG("ft_nmap: pcap_set_buffer_size failed\n");
		return FAILURE;
	}
	if (pcap_set_immediate_mode(handle, immediate_mode) != 0)
	{
		LOG("ft_nmap: pcap_set_immediate_mode failed\n");
		return FAILURE;
	}
	return SUCCESS;
}

static char *build_filter_expr(const char	  *ip_src_interface,
							   const t_target *targets, size_t target_count,
							   int iface_index)
{
	/* Guard against overflow: each target IP needs at most 30 chars.
	 * On 32-bit builds, SIZE_MAX/30 is the safe upper bound. */
	if (target_count > (SIZE_MAX - 100) / 30)
	{
		LOG("ft_nmap: too many targets for pcap filter\n");
		return NULL;
	}
	const size_t filter_len = 100 + 30 * target_count;
	char		*filter_expr = malloc(filter_len);
	if (!filter_expr)
	{
		LOG("ft_nmap: malloc failed for filter expression\n");
		return NULL;
	}

	int n = snprintf(filter_expr, filter_len,
					 "(tcp or udp or icmp) and dst host %s", ip_src_interface);
	if (n < 0 || (size_t)n >= filter_len)
	{
		LOG("ft_nmap: filter expression truncated\n");
		free(filter_expr);
		return NULL;
	}
	size_t off = (size_t)n;

	bool first_target = true;
	for (size_t i = 0; i < target_count; i++)
	{
		if (targets[i].iface_info->iface_index != iface_index)
			continue;

		char ip_buf[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &targets[i].addr, ip_buf, sizeof(ip_buf));

		n = snprintf(filter_expr + off, filter_len - off,
					 first_target ? " and (src host %s" : " or src host %s",
					 ip_buf);
		if (n < 0 || (size_t)n >= filter_len - off)
		{
			LOG("ft_nmap: filter expression truncated\n");
			free(filter_expr);
			return NULL;
		}
		off += (size_t)n;
		first_target = false;
	}
	if (!first_target)
	{
		n = snprintf(filter_expr + off, filter_len - off, ")");
		if (n < 0 || (size_t)n >= filter_len - off)
		{
			LOG("ft_nmap: filter expression truncated\n");
			free(filter_expr);
			return NULL;
		}
	}

	return filter_expr;
}

static int pcap_apply_filter(pcap_t *handle, const char *filter_expr)
{
	struct bpf_program fp;
	if (pcap_compile(handle, &fp, filter_expr, 1, PCAP_NETMASK_UNKNOWN) == -1)
	{
		LOG("pcap_compile failed: %s\n", pcap_geterr(handle));
		return FAILURE;
	}
	if (pcap_setfilter(handle, &fp) == -1)
	{
		LOG("pcap_setfilter failed: %s\n", pcap_geterr(handle));
		pcap_freecode(&fp);
		return FAILURE;
	}
	pcap_freecode(&fp);
	return SUCCESS;
}

int pcap_setup(t_receiver_data *pcap_ctx, char *errbuf, const t_target *targets,
			   size_t target_count)
{
	const char *ip_src_interface = inet_ntoa(pcap_ctx->iface_info->ip_addr);
	if (ip_src_interface == NULL)
	{
		LOG("ft_nmap: inet_ntoa failed\n");
		return FAILURE;
	}
	pcap_ctx->handle = pcap_create(pcap_ctx->iface_info->name, errbuf);
	if (!pcap_ctx->handle)
	{
		LOG("ft_nmap: pcap_create failed: %s\n", errbuf);
		return FAILURE;
	}
	// Configure the handle
	if (pcap_configure(pcap_ctx->handle, PCAP_SNAPLEN, PCAP_PROMISC,
					   PCAP_BUFFER_SIZE, PCAP_IMMEDIATE_MODE))
	{
		pcap_close(pcap_ctx->handle);
		return FAILURE;
	}
	// Activate the handle
	int rc = pcap_activate(pcap_ctx->handle);
	if (rc < 0)
	{
		LOG("ft_nmap: pcap_activate failed: %s\n",
			pcap_geterr(pcap_ctx->handle));
		pcap_close(pcap_ctx->handle);
		return FAILURE;
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
		return FAILURE;
	}

	if (pcap_apply_filter(pcap_ctx->handle, filter_expr))
	{
		LOG("ft_nmap: pcap_apply_filter failed\n");
		free(filter_expr);
		pcap_close(pcap_ctx->handle);
		return FAILURE;
	}
	free(filter_expr);
	return SUCCESS;
}
