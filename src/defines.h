#ifndef DEFINES_H
#define DEFINES_H

/* Program options */
#define HELP 1000
#define IP_MODE 1001
#define FILE_MODE 1002
#define PORTS 1003
#define SCAN 1004
#define SPEED 1005
#define PACKET_TRACE 1006
#define REASON 1007
#define VERBOSE 1008
#define VERSION_DETECT 1009
#define OS_DETECT 1010
#define DECOY 1011
/* Maximum number of decoy IPs the user can specify */
#define MAX_DECOYS 3
#define MIN_PORT_NUMBER 1
#define SCAN_INVALID 255
/* Maximum number of threads our program can run (option set with --speed)*/
#define SPEED_MAX 250
#define SPEED_MIN 0
#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0
/* Lengt of ethernet header */
#define ETH_ALEN 6
/* Maximum number of port a user can scan with one execution of the program */
#define MAX_PORT_COUNT 1024
/* Maximum port number possible */
#define MAX_PORT_NUMBER 65535
/* ??? */
#define MIN_SRC_PORT_NUMBER 1024
#define MAX_PROTO_COUNT 2
/* Number of type of scan a user can perform simultaneously */
#define MAX_NB_SCAN_TYPE 6
#define MAX_SCAN_TYPE_TCP 5
#define HIGHEST_PORT_STATE 6
#define IP_VERSION 4
#define IP_IHL 5
#define IP_TTL_DEFAULT 64
#define MAX_SCAN_RETRIES 1
/* Timeout after which we consider the server didn't responde us */
#define TIMEOUT_DELAY 0.3
/* Index used in final_port_state */
#define TCP_INDEX 0
#define UDP_INDEX 1

#define MAX_REASONS_NUMBER 2

#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_BLUE "\x1b[34m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_CYAN "\x1b[36m"
#define ANSI_COLOR_RESET "\x1b[0m"
#define ANSI_BOLD "\x1b[1m"
#define ANSI_UNDERLINE "\x1b[4m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_RED "\x1b[31m"

/* Macro to set and verify an option is set */
#define SET(flags, flag) ((flags) |= (flag))
#define HAS(flags, flag) (((flags) & (flag)) != 0)

#include <stdlib.h>
#define LOG(fmt, ...)                                                          \
	do                                                                         \
	{                                                                          \
		if (getenv("TEST_MODE") == NULL)                                       \
		{                                                                      \
			fprintf(stderr, fmt, ##__VA_ARGS__);                               \
		}                                                                      \
	} while (0)

#endif // PARSING_H
