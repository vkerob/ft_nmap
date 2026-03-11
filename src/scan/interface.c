#include "scan.h"

#include <errno.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool add_unique_dev(t_iface_info **ifaces, struct in_addr local_addr,
						   size_t *iface_count, const char *ifname,
						   u8 *iface_index)
{

	for (size_t i = 0; i < *iface_count; i++)
	{
		if (strcmp((*ifaces)[i].name, ifname) == 0)
		{
			return false;
		}
	}

	if (*ifaces)
	{
		*ifaces = realloc(*ifaces, (*iface_count + 1) * sizeof(t_iface_info));
		if (!*ifaces)
		{
			fprintf(stderr, "ft_nmap: realloc failed: %s\n", strerror(errno));
			return true;
		}
	}
	else
	{
		*ifaces = calloc(*iface_count + 1, sizeof(t_iface_info));
		if (!*ifaces)
		{
			fprintf(stderr, "ft_nmap: calloc failed: %s\n", strerror(errno));
			return true;
		}
	}

	strncpy((*ifaces)[*iface_count].name, ifname, IFNAMSIZ);
	(*ifaces)[*iface_count].name[IFNAMSIZ - 1] = '\0';
	(*ifaces)[*iface_count].ip_addr = local_addr;
	*iface_index = (*iface_count)++;
	return false;
}

static void ifname_from_ipv4(struct in_addr ip_addr, char *ifname_buf)
{
	struct ifaddrs *ifaddr, *ifa;
	if (getifaddrs(&ifaddr) == -1)
	{
		perror("getifaddrs");
		strncpy(ifname_buf, "unknown", IFNAMSIZ);
		return;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET)
			continue;

		// in the future, we might want to get the mac address
		struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
		if (sa->sin_addr.s_addr == ip_addr.s_addr)
		{
			strncpy(ifname_buf, ifa->ifa_name, IFNAMSIZ);
			freeifaddrs(ifaddr);
			return;
		}
	}

	strncpy(ifname_buf, "unknown", IFNAMSIZ);
	freeifaddrs(ifaddr);
}

// bool get_iface_info(char (**iface_names)[IFNAMSIZ], size_t *iface_count,
//					t_target *targets, size_t target_count)
bool get_iface_info(t_iface_info **ifaces, size_t *iface_count,
					t_target *targets, size_t target_count)
{
	u8 iface_index = 0;

	for (size_t i = 0; i < target_count; i++)
	{
		// udp trick to get the local IP address that would be used to reach the
		// target and the corresponding interface
		int fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd == -1)
		{
			perror("socket");
			return true;
		}

		struct sockaddr_in dst_addr;
		memset(&dst_addr, 0, sizeof(dst_addr));

		dst_addr.sin_family = AF_INET;
		dst_addr.sin_addr = targets[i].addr; // <- in_addr
		dst_addr.sin_port
			= htons(53); // arbitrary port, we won't actually send data

		// Connect the socket to the target address. This doesn't send any
		// packets because it's a UDP socket, but it will cause the kernel to
		// assign a local IP address and interface to the socket based on the
		// routing table.
		int rc = connect(fd, (struct sockaddr *)&dst_addr,
						 sizeof(struct sockaddr_in));
		if (rc == -1)
		{
			perror("connect");
			close(fd);
			return true;
		}

		struct sockaddr_in local_addr;
		socklen_t		   local_addr_len = sizeof(local_addr);
		// Now we can call getsockname to get the local address assigned to the
		// socket, which will be the IP address of the interface that would be
		// used to reach the target. (our source IP in packets sent to the
		// target)
		if (getsockname(fd, (struct sockaddr *)&local_addr, &local_addr_len)
			== -1)
		{
			perror("getsockname");
			close(fd);
			return true;
		}
		close(fd);

		char ifname_buf[IFNAMSIZ];

		ifname_from_ipv4(local_addr.sin_addr, ifname_buf);

		if (add_unique_dev(ifaces, local_addr.sin_addr, iface_count, ifname_buf,
						   &iface_index))
		{
			fprintf(stderr, "ft_nmap: Failed to add interface name\n");
			return true;
		}
		targets[i].iface_info = &(*ifaces[iface_index]);
	}
	return false;
}
