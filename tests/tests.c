#include "tests.h"
#include "greatest.h"
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>

extern SUITE(parsing_suite);
extern SUITE(scan_suite);

GREATEST_MAIN_DEFS();

sig_atomic_t volatile g_stop = 0;

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
		close(fd);
		return -1;
	}
	return fd;
}

static void build_port_arg(t_socket *sockets, int n, char *buf, size_t bufsz)
{
	int written = 0;
	for (int i = 0; i < n; i++)
	{
		int ret;
		if (i == 0)
		{
			ret = snprintf(buf, bufsz - written, "%d", sockets[i].port);
		}
		else
			ret = snprintf(buf + written, bufsz - written, ",%d",
						   sockets[i].port);
		if (ret < 0 || (size_t)ret >= bufsz - written)
			break;
		written += ret;
	}
}

/* ------------------------------------------------------------------ */
/*  greatest setup / teardown callbacks                                 */
/* ------------------------------------------------------------------ */

void init_servers(void *data)
{
	(void)data;
	g_server_data = calloc(1, sizeof(t_server));
	// t_server *server = (t_server *)data;
	// memset(server, 0, sizeof(*server));

	/* Seed differently on each run */
	srand((unsigned)time(NULL) ^ (unsigned)getpid());

	int max_port_nb_tcp = 1 + rand() % 10;
	int max_port_nb_udp = 1 + rand() % 10;
	// g_server_data = calloc(1, sizeof(t_server));

	/* --- TCP --- */
	for (int i = 0; i < max_port_nb_tcp;)
	{
		int port = random_port();
		int fd = open_tcp_port(port);
		if (fd < 0)
			continue; /* port busy, try another */
		g_server_data->tcp_sockets[i].fd = fd;
		g_server_data->tcp_sockets[i].port = port;
		i++;
	}
	g_server_data->nb_open_sock_tcp = max_port_nb_tcp;

	/* --- UDP --- */
	for (int i = 0; i < max_port_nb_udp;)
	{
		int port = random_port();
		int fd = open_udp_port(port);
		if (fd < 0)
			continue;
		g_server_data->udp_sockets[i].fd = fd;
		g_server_data->udp_sockets[i].port = port;
		i++;
	}
	g_server_data->nb_open_sock_udp = max_port_nb_udp;
	/* Build the port-argument strings for nmap / ft_nmap */
	build_port_arg(g_server_data->tcp_sockets, g_server_data->nb_open_sock_tcp,
				   g_server_data->tcp_arg_port,
				   sizeof(g_server_data->tcp_arg_port));
	build_port_arg(g_server_data->udp_sockets, g_server_data->nb_open_sock_udp,
				   g_server_data->udp_arg_port,
				   sizeof(g_server_data->udp_arg_port));

	printf("[setup] TCP ports : %s\n", g_server_data->tcp_arg_port);
	printf("[setup] UDP ports : %s\n", g_server_data->udp_arg_port);
}

void close_servers(void *data)
{
	t_server *td = (t_server *)data;

	for (int i = 0; i < td->nb_open_sock_tcp; i++)
		close(td->tcp_sockets[i].fd);
	for (int i = 0; i < td->nb_open_sock_udp; i++)
		close(td->udp_sockets[i].fd);
}

/* ------------------------------------------------------------------ */
/*  Entry point                                                         */
/* ------------------------------------------------------------------ */

int main(const int argc, char **argv)
{
	GREATEST_MAIN_BEGIN();

	// RUN_SUITE(parsing_suite);

	// SET_SETUP(init_servers, NULL); SET_TEARDOWN(close_servers, NULL);

	init_servers(NULL);
	RUN_SUITE(scan_suite);

	GREATEST_MAIN_END();
}
