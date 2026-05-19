#ifndef TESTS_H
#define TESTS_H

#define MAX_PORT_NUMBER 1024
typedef struct s_socket
{
	int fd;
	int port;
} t_socket;

typedef struct s_server
{
	t_socket udp_sockets[MAX_PORT_NUMBER];
	t_socket tcp_sockets[MAX_PORT_NUMBER];
	int		 nb_open_sock_udp;
	int		 nb_open_sock_tcp;
	char	 tcp_arg_port[65536];
	char	 udp_arg_port[65536];
} t_server;

#endif