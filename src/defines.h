#ifndef DEFINES_H
#define DEFINES_H

#define HELP 1000
#define IP_MODE 1001
#define FILE_MODE 1002
#define PORTS 1003
#define SCAN 1004
#define SPEED 1005
#define PACKET_TRACE 1006
#define MIN_PORT_NUMBER 1
#define SCAN_INVALID 255
#define SPEED_MAX 250
#define SPEED_MIN 0
#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0
#define ETH_ALEN 6
#define MAX_PORT_COUNT 1024
#define MAX_PORT_NUMBER 65535
#define MIN_SRC_PORT_NUMBER 1024
#define MAX_PROTO_COUNT 2
#define MAX_NB_SCAN_TYPE 6
#define MAX_SCAN_TYPE_TCP 5
#define HIGHEST_PORT_STATE 3
#define IP_VERSION 4
#define IP_IHL 5
#define IP_TTL_DEFAULT 64
#define MAX_SCAN_RETRIES 1
#define TIMEOUT_DELAY 0.3

#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_BLUE "\x1b[34m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_CYAN "\x1b[36m"
#define ANSI_COLOR_RESET "\x1b[0m"
#define ANSI_BOLD "\x1b[1m"
#define ANSI_UNDERLINE "\x1b[4m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_RED "\x1b[31m"

#define SET(flags, flag) ((flags) |= (flag))
#define HAS(flags, flag) (((flags) & (flag)) != 0)

#endif // PARSING_H
