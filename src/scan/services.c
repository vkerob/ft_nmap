
#include "args.h"
#include "commons.h"
#include "debug.h"
#include "my_signal.h"
#include "parsing.h"
#include "scan.h"
#include "shared.h"
#include "utils.h"

#include <pcap/pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <regex.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>


bool resolve_services_name(u16 port_count, int *port_map,
								 t_port_svc *(*arr)[MAX_PROTO_COUNT], bool udp_scan, bool tcp_scan)
{
	PCRE2_SIZE error_offset;
	pcre2_code *re = NULL;
	char pattern[512] = { 0 };
	int error_number;
	u16 port_co = 0;
	bool ret = false;

  if (tcp_scan)
  {
    (*arr)[TCP_INDEX] = calloc(port_count, sizeof(t_port_svc));
    if ((*arr)[TCP_INDEX] == NULL)
    {
      LOG("ft_nmap: calloc: '%s'\n", strerror(errno));
			ret = true;
			goto cleanup;
    }
  }

  if (udp_scan)
  {
    (*arr)[UDP_INDEX] = calloc(port_count, sizeof(t_port_svc));
    if ((*arr)[UDP_INDEX] == NULL)
    {
      LOG("ft_nmap: calloc: '%s'\n", strerror(errno));
			ret = true;
			goto cleanup;
    }
  }

	FILE *fp = fopen("/usr/share/nmap/nmap-services", "r");
	if (!fp)
	{
		LOG("ft_nmap: unable to open nmap-services file, resort to /etc/services\n");
		fp = fopen("/etc/services", "r");
		if (!fp)
		{
			LOG("ft_nmap: unable to read services file\n");
			ret = true;
			goto cleanup;
		}
	}
	// This file contains a list of services running on each port in general for both protocols (tcp and udp)
	snprintf(pattern, sizeof(pattern),
	"([a-zA-Z0-9]+)\\s+([0-9]{1,5})/([a-z]+).*$\n");

	re = pcre2_compile(
		(unsigned char *)pattern,
		PCRE2_ZERO_TERMINATED,
		0,
		&error_number,
		&error_offset,
		NULL);

	if (re == NULL)
	{
		LOG("Invalid pattern: %s\n", pattern);
		return true;
	}

	int line_nb = 0;

	int rc = -1;

	char buffer[256];
	while (fgets(buffer, sizeof(buffer), fp) != NULL && port_co < port_count) {
		line_nb++;
		pcre2_match_data *match_data =
		pcre2_match_data_create_from_pattern(re, NULL);
		rc = pcre2_match(
			re,
			(unsigned char *)buffer,
			strlen(buffer),
			0,
			0,
			match_data,
			NULL);
		if (rc == PCRE2_ERROR_NOMATCH)
		{
			pcre2_match_data_free(match_data);
			memset(buffer, 0, sizeof(buffer));
			continue ;
		}
		else if (rc < 0)
		{
			pcre2_match_data_free(match_data);
			LOG("ft_nmap: pcre2_match: Matching error\n");
			fclose(fp);
			break ;
		}
		else
		{
			PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
			if (ovector == NULL)
			{
				LOG("ft_nmap: pcre2_get_ovector_pointer: %s\n", strerror(errno));
				pcre2_match_data_free(match_data);
				pcre2_code_free(re);
				fclose(fp);
				return true;
			}

			char *protocol = NULL;
			char *port = NULL;
			char *service = NULL;

  
			if (substr(buffer, ovector[2], ovector[3], &service) ||
				substr(buffer, ovector[4], ovector[5], &port) ||
				substr(buffer, ovector[6], ovector[7], &protocol))
			{
				better_free(service);
				better_free(protocol);
				better_free(port);
				ret = true;
				goto cleanup;
			}

			pcre2_match_data_free(match_data);
			char *endptr;
			intmax_t port_nb = strtoimax(port, &endptr, 10);

			if (port_nb == 0 && *port == '\0')
			{
				better_free(service);
				better_free(protocol);
				better_free(port);
				LOG("ft_nmap: error at line %d\n", line_nb);
				memset(buffer, 0, sizeof(buffer));
				continue ;
			}

			const int idx = port_map[port_nb];
			// Means it's a port that's not scanned
			if (idx == -1)
			{
				better_free(service);
				better_free(protocol);
				better_free(port);
				memset(buffer, 0, sizeof(buffer));
				continue ;
			}
			port_co++;
			if (tcp_scan && strcmp(protocol, "tcp") == 0)
			{
				(*arr)[TCP_INDEX][idx].port = port_nb;
				(*arr)[TCP_INDEX][idx].name = service;
			}
			else if (udp_scan && strcmp(protocol, "udp") == 0)
			{
				(*arr)[UDP_INDEX][idx].port = port_nb;
				(*arr)[UDP_INDEX][idx].name = service;
			}
			else{
				better_free(service);

			}
			// else if (strcmp(protocol, "udp") != 0 && strcmp(protocol, "tcp") != 0){
			// 	LOG("ft_nmap: error at line %d: unknown protocol\n", line_nb);
			// 	ret = true;
			// 	better_free(service);
			// 	better_free(protocol);
			// 	better_free(port);
			// 	goto cleanup;
			// }
				better_free(protocol);
				better_free(port);
			memset(buffer, 0, sizeof(buffer));
		}
	}
	for (u16 i = 0; i < port_count; i++){
		if (udp_scan && (*arr)[UDP_INDEX][i].name == NULL)
		{
			(*arr)[UDP_INDEX][i].name = strdup("unknown");
		}
		if (tcp_scan && (*arr)[TCP_INDEX][i].name == NULL)
		{
			(*arr)[TCP_INDEX][i].name = strdup("unknown");
		}
	}
	pcre2_code_free(re);
	fclose(fp);
	return ret;

	cleanup:
		if (fp)
		{
			fclose(fp);
		}
		if (re)
		{
			pcre2_code_free(re);
		}
		better_free((*arr)[TCP_INDEX]);
		better_free((*arr)[UDP_INDEX]);
		return ret;
}


void free_services(t_port_svc *(*head)[MAX_PROTO_COUNT], u16 port_count)
{
	(void)port_count;
	if ((*head)[TCP_INDEX])
	{
		for (u16 i = 0; i < port_count; i++)
		{
			better_free((*head)[TCP_INDEX][i].name);
		}
		free((*head)[TCP_INDEX]);
		(*head)[TCP_INDEX] = NULL;
	}
	if ((*head)[UDP_INDEX])
	{
		for (u16 i = 0; i < port_count; i++)
		{
			better_free((*head)[UDP_INDEX][i].name);
		}
		free((*head)[UDP_INDEX]);
		(*head)[UDP_INDEX] = NULL;
	}
}
