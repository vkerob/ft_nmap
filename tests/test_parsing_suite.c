#include "greatest.h"
#include "parsing.h"
#include "typesdef.h"
#include <getopt.h>
#include <string.h>

SUITE(parsing_suite);

TEST parse_ports_parses_single_port(void)
{
	u16 ports[1024];
	u16 port_count = 0;

	ASSERT_FALSE(parse_ports("80", ports, &port_count));
	ASSERT_EQ(1, port_count);
	ASSERT_EQ(80, ports[0]);
	PASS();
}

TEST parse_ports_parses_multiple_port(void)
{
	u16 ports[1024];
	u16 port_count = 0;

	ASSERT_FALSE(parse_ports("80,,81", ports, &port_count));
	ASSERT_EQ(2, port_count);
	ASSERT_EQ(80, ports[0]);
	ASSERT_EQ(81, ports[1]);
	PASS();
}

TEST parse_ports_rejects_invalid_port(void)
{
	u16 ports[1024];
	u16 port_count = 0;

	ASSERT(parse_ports("abc", ports, &port_count));
	ASSERT_EQ(0, port_count);
	PASS();
}

TEST parse_ports_parses_range(void)
{
	u16 ports[1024];
	u16 port_count = 0;

	ASSERT_FALSE(parse_ports("80-82", ports, &port_count));
	ASSERT_EQ(3, port_count);
	ASSERT_EQ(80, ports[0]);
	ASSERT_EQ(81, ports[1]);
	ASSERT_EQ(82, ports[2]);
	PASS();
}

TEST parse_ports_rejects_invalid_range(void)
{
	u16 ports[1024];
	u16 port_count = 0;

	ASSERT(parse_ports("90-80", ports, &port_count));
	ASSERT_EQ(0, port_count);
	PASS();
}

TEST parse_args_parses_scan_types(void)
{
	u8	 scan_types[6] = { 0 };
	u8	 nb_scan_type = 0;
	bool tcp_scan = false;
	bool udp_scan = false;

	ASSERT_FALSE(parse_scan_types(strdup("SYN,ACK,UDP"), &scan_types,
								  &nb_scan_type, &tcp_scan, &udp_scan));
	ASSERT_EQ(nb_scan_type, 3);
	ASSERT_EQ(tcp_scan, true);
	ASSERT_EQ(udp_scan, true);
	ASSERT_EQ(scan_types[0], SCAN_SYN);
	ASSERT_EQ(scan_types[1], SCAN_ACK);
	ASSERT_EQ(scan_types[2], SCAN_UDP);
	PASS();
}



TEST parse_args_invalid_scan_returns_error(void)
{
	t_args args;
	char  *argv[] = { "ft_nmap", "--scan", "SYNN", NULL };
	int	   argc = 3;

	ASSERT(parse_args(argc, argv, &args, NULL, NULL));
	PASS();
}

TEST parse_args_invalid_option(void)
{
	t_args args;
	char  *argv[] = { "ft_nmap", "--test", NULL };
	int	   argc = 3;

	ASSERT(parse_args(argc, argv, &args, NULL, NULL));
	PASS();
}

SUITE(parsing_suite)
{
	RUN_TEST(parse_ports_parses_single_port);
	RUN_TEST(parse_ports_parses_multiple_port);
	RUN_TEST(parse_ports_parses_range);
	RUN_TEST(parse_ports_rejects_invalid_port);
	RUN_TEST(parse_ports_rejects_invalid_range);
	RUN_TEST(parse_args_invalid_option);
	RUN_TEST(parse_args_parses_scan_types);
	RUN_TEST(parse_args_invalid_scan_returns_error);
}
