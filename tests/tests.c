#include "tests.h"
#include "greatest.h"
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>

extern SUITE(parse_ports_suite);
extern SUITE(parse_scan_types_suite);
extern SUITE(parse_args_suite);
extern SUITE(scan_udp_suite);
extern SUITE(scan_syn_suite);
extern SUITE(scan_ack_suite);
extern SUITE(scan_stealth_suite);

GREATEST_MAIN_DEFS();

sig_atomic_t volatile g_stop = 0;
sig_atomic_t g_display_output;

t_server *g_server_data = NULL;

#define PORT_MIN 1024
#define PORT_MAX 65535

static int random_port(void)
{
	return PORT_MIN + rand() % (PORT_MAX - PORT_MIN + 1);
}

static int open_tcp_port(int port)
{
	int fd;

	struct sockaddr_in server_sockaddr_in;

	server_sockaddr_in.sin_family = AF_INET;

	server_sockaddr_in.sin_addr.s_addr = htonl(INADDR_ANY);

	server_sockaddr_in.sin_port = htons(port);

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
	{
		exit(EXIT_FAILURE);
	}

	int opt = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if (bind(fd, (struct sockaddr *)&server_sockaddr_in,
			 sizeof(server_sockaddr_in))
		< 0)
	{
		close(fd);
		return -1;
	}

	if (listen(fd, 5) < 0)
	{
		close(fd);
		return -1;
	}
	return fd;
}

static int open_udp_port(int port)
{
	struct sockaddr_in server_sockaddr_in;

	server_sockaddr_in.sin_family = AF_INET;

	server_sockaddr_in.sin_addr.s_addr = htonl(INADDR_ANY);

	server_sockaddr_in.sin_port = htons(port);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
	{
		return -1;
	}

	int opt = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	if (bind(fd, (struct sockaddr *)&server_sockaddr_in,
			 sizeof(server_sockaddr_in))
		< 0)
	{
		fprintf(stderr, "%s\n", strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

static void build_port_arg(t_socket *sockets, int n, char **ptr)
{
	int	   written = 0;
	size_t total_len = 0;
	char   buf[16] = { 0 };

	for (int i = 0; i < n; i++)
	{
		total_len += snprintf(buf, sizeof(buf), "%s%d", i ? "," : "",
							  sockets[i].port);
	}
	*ptr = malloc(total_len + 1);
	if (*ptr == NULL)
	{
		fprintf(stderr, "%s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	for (int i = 0; i < n; i++)
	{
		written += snprintf(*ptr + written, total_len + 1 - written, "%s%d",
							i ? "," : "", sockets[i].port);
	}
}

/* ------------------------------------------------------------------ */
/*  greatest setup / teardown callbacks                                 */
/* ------------------------------------------------------------------ */

static void init_servers(void)
{
	g_server_data = calloc(1, sizeof(t_server));

	srand((unsigned)time(NULL) ^ (unsigned)getpid());

	// Number of ports to scan by nmap/ft_nmap
	int max_port_nb_tcp = 1 + rand() % MAX_NUMBER_PORT_TO_SCAN;
	int max_port_nb_udp = 1 + rand() % MAX_NUMBER_PORT_TO_SCAN;

	/* --- TCP --- */
	for (int i = 0; i < max_port_nb_tcp;)
	{
		int port = random_port();
		g_server_data->tcp_sockets[i].port = port;
		int open = rand() % 2;
		if (open == 1)
		{
			int fd = open_tcp_port(port);
			if (fd < 0)
				continue; /* port busy, try another */
			g_server_data->tcp_sockets[i].fd = fd;
		}
		i++;
	}
	g_server_data->nb_open_sock_tcp = max_port_nb_tcp;

	/* --- UDP --- */
	for (int i = 0; i < max_port_nb_udp;)
	{
		int port = random_port();
		g_server_data->udp_sockets[i].port = port;

		// This add randomness so that we don't end up with only open port at
		// the end in our scan result
		int open = rand() % 2;
		if (open == 1)
		{
			int fd = open_udp_port(port);
			if (fd < 0)
				continue; /* port busy, try another */
			g_server_data->udp_sockets[i].fd = fd;
		}
		i++;
	}
	g_server_data->nb_open_sock_udp = max_port_nb_udp;
	/* Build the port-argument strings for nmap / ft_nmap which contains opened
	 * ports */

	build_port_arg(g_server_data->tcp_sockets, g_server_data->nb_open_sock_tcp,
				   &g_server_data->tcp_ports);
	build_port_arg(g_server_data->udp_sockets, g_server_data->nb_open_sock_udp,
				   &g_server_data->udp_ports);

	printf("[setup] TCP ports : %s\n", g_server_data->tcp_ports);
	printf("[setup] UDP ports : %s\n", g_server_data->udp_ports);
}

static void close_servers()
{
	for (int i = 0; i < g_server_data->nb_open_sock_tcp; i++)
	{
		if (g_server_data->tcp_sockets[i].fd > 0)
			close(g_server_data->tcp_sockets[i].fd);
	}
	for (int i = 0; i < g_server_data->nb_open_sock_udp; i++)
	{
		if (g_server_data->udp_sockets[i].fd > 0)
			close(g_server_data->udp_sockets[i].fd);
	}
}

/* ------------------------------------------------------------------ */
/*  Entry point                                                         */
/* ------------------------------------------------------------------ */

int main(const int argc, char **argv)
{
	GREATEST_MAIN_BEGIN();

	RUN_SUITE(parse_ports_suite);
	RUN_SUITE(parse_scan_types_suite);
	RUN_SUITE(parse_args_suite);

	// Scan suites share the same server setup
	init_servers();
	RUN_SUITE(scan_udp_suite);
	RUN_SUITE(scan_syn_suite);
	RUN_SUITE(scan_ack_suite);
	RUN_SUITE(scan_stealth_suite);
	close_servers();
	GREATEST_MAIN_END();
}
