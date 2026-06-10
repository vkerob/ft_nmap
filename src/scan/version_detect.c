#define PCRE2_CODE_UNIT_WIDTH 8
#define _GNU_SOURCE

#include "scan.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcre2.h>
#include <stdio.h>
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
**   4. Parse the raw banner into a human-friendly version string.
*/

#define BANNER_TIMEOUT_SEC 2
#define BANNER_BUF_SIZE    512

/* HTTP probe sent to silent services */
static const char *HTTP_PROBE = "HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n";

/*
** Match `pattern` against `subject` and copy capture group `group` into `out`.
** Returns 1 on success, 0 if no match or error.
*/
static int regex_capture(const char *pattern, const char *subject,
                          size_t subj_len, int group,
                          char *out, size_t out_size)
{
    int        errcode;
    PCRE2_SIZE erroffset;

    pcre2_code *re = pcre2_compile(
        (PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED,
        PCRE2_CASELESS, &errcode, &erroffset, NULL);
    if (!re)
        return 0;

    pcre2_match_data *md = pcre2_match_data_create_from_pattern(re, NULL);
    int rc = pcre2_match(re, (PCRE2_SPTR)subject, subj_len, 0, 0, md, NULL);

    int ret = 0;
    if (rc > group)
    {
        PCRE2_SIZE *ov    = pcre2_get_ovector_pointer(md);
        PCRE2_SIZE  start = ov[2 * group];
        PCRE2_SIZE  end   = ov[2 * group + 1];
        size_t      len   = end - start;
        if (len >= out_size)
            len = out_size - 1;
        memcpy(out, subject + start, len);
        out[len] = '\0';
        ret = 1;
    }

    pcre2_match_data_free(md);
    pcre2_code_free(re);
    return ret;
}

/*
** Sanitise the raw banner: keep the first non-empty line, strip \r\n and
** non-printable bytes so the terminal output stays clean.
*/
static void sanitise_banner(char *buf, size_t buf_size)
{
    char *nl = strchr(buf, '\n');
    if (nl)
        *nl = '\0';
    char *cr = strchr(buf, '\r');
    if (cr)
        *cr = '\0';

    char *start = buf;
    while (*start == ' ' || *start == '\t')
        start++;

    for (char *p = start; *p; p++)
    {
        if ((unsigned char)*p < 0x20 || (unsigned char)*p == 0x7f)
            *p = '.';
    }

    if (start != buf)
    {
        size_t len = strlen(start);
        if (len >= buf_size)
            len = buf_size - 1;
        memmove(buf, start, len + 1);
    }
}

/*
** Parse known banner formats into a nmap-style version string.
** Returns 1 if the banner was recognised and out was filled, 0 otherwise.
**
** Patterns (PCRE2, case-insensitive):
**   SSH   — ^SSH-([^-\r\n]+)-(\S+)         groups: 1=proto  2=software
**   FTP   — ^220 ([^\r\n]+)                 group:  1=text
**   SMTP  — ^220 ([^\r\n]+)                 group:  1=text
**   POP3  — ^\+OK ([^\r\n]+)               group:  1=text
**   IMAP  — ^\* OK ([^\r\n]+)              group:  1=text
**   HTTP  — \r?\nServer: ([^\r\n]+)         group:  1=server value
*/
static int parse_banner(const char *raw, char *out, size_t out_size)
{
    size_t raw_len = strlen(raw);
    char   software[128];
    char   proto[32];

    /* SSH: SSH-<proto>-<software> */
    if (regex_capture("^SSH-([^-\\r\\n]+)-([^\\r\\n ]+)",
                      raw, raw_len, 2, software, sizeof(software))
     && regex_capture("^SSH-([^-\\r\\n]+)-([^\\r\\n ]+)",
                      raw, raw_len, 1, proto, sizeof(proto)))
    {
        for (char *p = software; *p; p++)
            if (*p == '_') *p = ' ';
        snprintf(out, out_size, "%s (protocol %s)", software, proto);
        return 1;
    }

    /* FTP / SMTP: 220 <text> */
    if (regex_capture("^220 ([^\\r\\n]+)", raw, raw_len, 1, out, out_size))
        return 1;

    /* POP3: +OK <text> */
    if (regex_capture("^\\+OK ([^\\r\\n]+)", raw, raw_len, 1, out, out_size))
        return 1;

    /* IMAP: * OK <text> */
    if (regex_capture("^\\* OK ([^\\r\\n]+)", raw, raw_len, 1, out, out_size))
        return 1;

    /* HTTP: Server: <value> anywhere in the response */
    if (regex_capture("\\r?\\nServer: ([^\\r\\n]+)", raw, raw_len, 1, out, out_size))
        return 1;

    return 0;
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
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(port);
    sa.sin_addr        = target_addr;

    if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) != 0)
    {
        close(sock);
        return;
    }

    char    buf[BANNER_BUF_SIZE];
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
        if (!parse_banner(buf, out, out_size))
        {
            sanitise_banner(buf, sizeof(buf));
            if (buf[0] != '\0')
                strncpy(out, buf, out_size - 1);
        }
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
        const int idx  = target->port_list.port_map[port];
        if (idx < 0)
            continue;

        t_port_output *po = &target->port_list.port_final_state[TCP_INDEX][idx];
        if (po->port_state != OPEN)
            continue;

        grab_banner(target->addr, port, po->version, sizeof(po->version));
    }
}
