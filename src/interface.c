#include "ft_nmap.h"
#include <ifaddrs.h>

static bool add_unique_dev(char (**dev_names)[IFNAMSIZ], size_t *dev_count,
						   const char *ifname)
{
	for (size_t i = 0; i < *dev_count; i++)
		if (strcmp((*dev_names)[i], ifname) == 0)
			return false;

	char (*tmp)[IFNAMSIZ]
		= realloc(*dev_names, (*dev_count + 1) * sizeof(**dev_names));
	if (!tmp)
		return true;
	*dev_names = tmp;

	strncpy((*dev_names)[*dev_count], ifname, IFNAMSIZ);
	(*dev_names)[*dev_count][IFNAMSIZ - 1] = '\0';

	(*dev_count)++;
	return false;
}

static void ifname_from_ipv4(struct in_addr ip_addr, char *ifname_buf,
							 size_t buf_size)
{
	struct ifaddrs *ifaddr, *ifa;
	if (getifaddrs(&ifaddr) == -1)
	{
		perror("getifaddrs");
		strncpy(ifname_buf, "unknown", buf_size);
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
			strncpy(ifname_buf, ifa->ifa_name, buf_size);
			freeifaddrs(ifaddr);
			return;
		}
	}

	strncpy(ifname_buf, "unknown", buf_size);
	freeifaddrs(ifaddr);
}

bool get_iface_info(char (**dev_names)[IFNAMSIZ], size_t *dev_count,
					t_target *targets, size_t target_count)
{
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

		struct sockaddr_in dst_addr = targets[i].addr;
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
		// used to reach the target. (our source IP in packets sent to the target)
		if (getsockname(fd, (struct sockaddr *)&local_addr, &local_addr_len)
			== -1)
		{
			perror("getsockname");
			close(fd);
			return true;
		}
		close(fd);

		targets[i].iface_info.ip_addr = local_addr.sin_addr;

		ifname_from_ipv4(local_addr.sin_addr, targets[i].iface_info.name,
						 sizeof(targets[i].iface_info.name));

		if (add_unique_dev(dev_names, dev_count, targets[i].iface_info.name))
		{
			fprintf(stderr, "ft_nmap: Failed to add interface name\n");
			return true;
		}
	}
	return false;
}
