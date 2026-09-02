#ifndef TESTS_H
#define TESTS_H

#define MAX_NUMBER_PORT_TO_SCAN 25

typedef struct s_socket
{
	int fd;
	int port;
} t_socket;

typedef struct s_server
{
	t_socket udp_sockets[MAX_NUMBER_PORT_TO_SCAN];
	t_socket tcp_sockets[MAX_NUMBER_PORT_TO_SCAN];
	int		 nb_open_sock_udp;
	int		 nb_open_sock_tcp;
	char	*tcp_ports;
	char	*udp_ports;
} t_server;

typedef struct s_port
{
	char 			*port;
	char		  *port_state;
	char		  *service;
	char			*protocol;
	struct s_port *next;
} t_port;

#endif