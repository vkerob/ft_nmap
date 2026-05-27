#include "scan.h" // t_target, t_args, t_port_output, PORT(), OPEN, TCP_INDEX

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/*
** Banner grabbing strategy:
**   1. Open a real TCP connection to the open port (2s timeout).
**   2. Wait briefly for a spontaneous banner (SSH, FTP, SMTP, POP3... send
**      one immediately on connect).
**   3. If nothing arrives, send a minimal HTTP probe — catches nginx, Apache,
**      and anything HTTP-based.
**   4. Store only the first non-empty line in port_output->version.
*/

#define BANNER_TIMEOUT_SEC 2
#define BANNER_BUF_SIZE 512

/* HTTP probe sent to silent services */
static const char *HTTP_PROBE = "HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n";

/*
** Sanitise the raw banner: keep the first non-empty line, strip \r\n and
** non-printable bytes so the terminal output stays clean.
*/
static void sanitise_banner(char *buf, size_t buf_size)
{
	/* Truncate at first newline */
	char *nl = strchr(buf, '\n');
	if (nl)
		*nl = '\0';
	char *cr = strchr(buf, '\r');
	if (cr)
		*cr = '\0';

	/* Strip leading whitespace */
	char *start = buf;
	while (*start == ' ' || *start == '\t')
		start++;

	/* Replace non-printable characters with '.' */
	for (char *p = start; *p; p++)
	{
		if ((unsigned char)*p < 0x20 || (unsigned char)*p == 0x7f)
			*p = '.';
	}

	/* Copy back to buf if we moved start */
	if (start != buf)
	{
		size_t len = strlen(start);
		if (len >= buf_size)
			len = buf_size - 1;
		memmove(buf, start, len + 1);
	}
}

static void grab_banner(struct in_addr target_addr, u16 port, char *out,
						size_t out_size)
{
	out[0] = '\0';

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		return;

	/* 2-second timeout for both connect and recv */
	struct timeval tv = { .tv_sec = BANNER_TIMEOUT_SEC, .tv_usec = 0 };
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr = target_addr;

	if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) != 0)
	{
		close(sock);
		return;
	}

	char buf[BANNER_BUF_SIZE];
	memset(buf, 0, sizeof(buf));

	/* First attempt: passive read (SSH, FTP, SMTP send banner on connect) */
	ssize_t n = recv(sock, buf, sizeof(buf) - 1, 0);

	if (n <= 0)
	{
		/* No spontaneous banner: try HTTP probe */
		send(sock, HTTP_PROBE, strlen(HTTP_PROBE), 0);
		memset(buf, 0, sizeof(buf));
		n = recv(sock, buf, sizeof(buf) - 1, 0);
	}

	if (n > 0)
	{
		buf[n] = '\0';
		sanitise_banner(buf, sizeof(buf));
		if (buf[0] != '\0')
			strncpy(out, buf, out_size - 1);
	}

	close(sock);
}

/*
** Public entry point: iterate over all scanned ports, and for each TCP port
** whose final state is OPEN, attempt banner grabbing and store the result in
** port_final_state[TCP_INDEX][idx].version.
*/
void grab_versions(t_target *target, t_args *args)
{
	if (!args->tcp_scan)
		return;

	for (u16 i = 0; i < args->port_count; i++)
	{
		const u16 port = args->ports[i];
		const int idx = target->port_list.port_map[PORT(port)];
		if (idx < 0)
			continue;

		t_port_output *po = &target->port_list.port_final_state[TCP_INDEX][idx];
		if (po->port_state != OPEN)
			continue;

		grab_banner(target->addr, port, po->version, sizeof(po->version));
	}
}
