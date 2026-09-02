#include "greatest.h"
#include "parsing.h"
#include "scan.h"
#include "typesdef.h"
#include <getopt.h>
#include <netinet/in.h>
#include <string.h>

SUITE(parse_ports_suite);
SUITE(parse_scan_types_suite);
SUITE(parse_args_suite);

/* ------------------------------------------------------------------ */
/*  parse_ports                                                         */
/* ------------------------------------------------------------------ */

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

	ASSERT_FALSE(parse_ports("80,81", ports, &port_count));
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

	/* Non-numeric end: "80-abc" — different from the reversed-range check below */
	ASSERT(parse_ports("80-abc", ports, &port_count));
	PASS();
}

TEST parse_ports_accepts_port_zero(void)
{
	u16 ports[1];
	u16 port_count = 0;

	ASSERT_FALSE(parse_ports("0", ports, &port_count));
	ASSERT_EQ(1, port_count);
	ASSERT_EQ(0, ports[0]);
	PASS();
}

TEST parse_ports_accepts_max_port(void)
{
	u16 ports[1];
	u16 port_count = 0;

	ASSERT_FALSE(parse_ports("65535", ports, &port_count));
	ASSERT_EQ(1, port_count);
	ASSERT_EQ(65535, ports[0]);
	PASS();
}

TEST parse_ports_rejects_out_of_range(void)
{
	u16 ports[1];
	u16 port_count = 0;

	ASSERT(parse_ports("65536", ports, &port_count));
	PASS();
}

TEST parse_ports_ignores_duplicate(void)
{
	u16 ports[10];
	u16 port_count = 0;

	/* Duplicate ports are silently skipped – not an error */
	ASSERT_FALSE(parse_ports("80,80,81", ports, &port_count));
	ASSERT_EQ(2, port_count);
	ASSERT_EQ(80, ports[0]);
	ASSERT_EQ(81, ports[1]);
	PASS();
}

TEST parse_ports_accepts_multiple_ranges(void)
{
	u16 ports[10];
	u16 port_count = 0;

	ASSERT_FALSE(parse_ports("80-82,90-91", ports, &port_count));
	ASSERT_EQ(5, port_count);
	ASSERT_EQ(80, ports[0]);
	ASSERT_EQ(81, ports[1]);
	ASSERT_EQ(82, ports[2]);
	ASSERT_EQ(90, ports[3]);
	ASSERT_EQ(91, ports[4]);
	PASS();
}

TEST parse_ports_rejects_range_too_large(void)
{
	u16 ports[1024];
	u16 port_count = 0;

	/* port_right - port_left > 1024 is rejected outright */
	ASSERT(parse_ports("1-1026", ports, &port_count));
	PASS();
}

TEST parse_ports_rejects_reversed_range(void)
{
	u16 ports[1024];
	u16 port_count = 0;

	/* port_left > port_right must be rejected */
	ASSERT(parse_ports("90-80", ports, &port_count));
	PASS();
}

TEST parse_ports_accepts_extra_commas(void)
{
	u16 ports[1024];
	u16 port_count = 0;

	/* strtok treats consecutive/leading/trailing commas as a single
	 * delimiter and never returns an empty token.  The empty-token guard
	 * inside parse_ports is therefore dead code; these strings are all
	 * silently accepted.  This test documents the current behaviour. */
	port_count = 0;
	ASSERT_FALSE(parse_ports("80,,81", ports, &port_count));
	ASSERT_EQ(2, port_count);

	port_count = 0;
	ASSERT_FALSE(parse_ports(",80", ports, &port_count));
	ASSERT_EQ(1, port_count);

	port_count = 0;
	ASSERT_FALSE(parse_ports("80,", ports, &port_count));
	ASSERT_EQ(1, port_count);
	PASS();
}

TEST parse_ports_rejects_double_dash(void)
{
	u16 ports[1024];
	u16 port_count = 0;

	/* A second dash inside a range token is invalid */
	ASSERT(parse_ports("80-90-100", ports, &port_count));
	PASS();
}


/* ------------------------------------------------------------------ */
/*  parse_scan_types                                                    */
/* ------------------------------------------------------------------ */

TEST parse_args_parses_scan_types(void)
{
	u8	 scan_types[6] = { 0 };
	u8	 nb_scan_type = 0;
	bool tcp_scan = false;
	bool udp_scan = false;
	char *arg = strdup("SYN,ACK,UDP");
	
	ASSERT(parse_scan_types(arg, &scan_types,
								  &nb_scan_type, &tcp_scan, &udp_scan) == SUCCESS);
	free(arg);
	ASSERT_EQ(nb_scan_type, 3);
	ASSERT_EQ(tcp_scan, true);
	ASSERT_EQ(udp_scan, true);
	ASSERT_EQ(scan_types[0], SCAN_SYN);
	ASSERT_EQ(scan_types[1], SCAN_ACK);
	ASSERT_EQ(scan_types[2], SCAN_UDP);
	PASS();
}

TEST parse_scan_types_all_types(void)
{
	u8   scan_types[MAX_NB_SCAN_TYPE] = { 0 };
	u8   nb_scan_type = 0;
	bool tcp_scan = false;
	bool udp_scan = false;
	char *arg = strdup("SYN,NULL,ACK,FIN,XMAS,UDP");

	ASSERT(parse_scan_types(arg,
								  &scan_types, &nb_scan_type, &tcp_scan,
								  &udp_scan) == SUCCESS);
	free(arg);
	ASSERT_EQ(6, nb_scan_type);
	ASSERT_EQ(true, tcp_scan);
	ASSERT_EQ(true, udp_scan);
	ASSERT_EQ(SCAN_SYN,  scan_types[0]);
	ASSERT_EQ(SCAN_NULL, scan_types[1]);
	ASSERT_EQ(SCAN_ACK,  scan_types[2]);
	ASSERT_EQ(SCAN_FIN,  scan_types[3]);
	ASSERT_EQ(SCAN_XMAS, scan_types[4]);
	ASSERT_EQ(SCAN_UDP,  scan_types[5]);
	PASS();
}

TEST parse_scan_types_rejects_duplicate(void)
{
	u8   scan_types[MAX_NB_SCAN_TYPE] = { 0 };
	u8   nb_scan_type = 0;
	bool tcp_scan = false;
	bool udp_scan = false;
	char *arg = strdup("SYN,SYN");

	ASSERT(parse_scan_types(arg, &scan_types, &nb_scan_type,
							&tcp_scan, &udp_scan) == FAILURE);
	free(arg);
	PASS();
}

TEST parse_scan_types_case_insensitive(void)
{
	u8   scan_types[MAX_NB_SCAN_TYPE] = { 0 };
	u8   nb_scan_type = 0;
	bool tcp_scan = false;
	bool udp_scan = false;
	char *arg = strdup("syn,udp");

	ASSERT(parse_scan_types(arg, &scan_types, &nb_scan_type,
								  &tcp_scan, &udp_scan) == SUCCESS);
	free(arg);
	ASSERT_EQ(2, nb_scan_type);
	ASSERT_EQ(SCAN_SYN, scan_types[0]);
	ASSERT_EQ(SCAN_UDP, scan_types[1]);
	PASS();
}

TEST parse_scan_types_rejects_empty_string(void)
{
	u8   scan_types[MAX_NB_SCAN_TYPE] = { 0 };
	u8   nb_scan_types = 0;
	bool tcp_scan = false, udp_scan = false;
	char *arg = strdup("");

	/* An empty scan string must fail (no type selected) */
	ASSERT(parse_scan_types(arg, &scan_types, &nb_scan_types, &tcp_scan, &udp_scan) == FAILURE);
	free(arg);
	PASS();
}

TEST parse_scan_types_accepts_trailing_comma(void)
{
	u8   scan_types[MAX_NB_SCAN_TYPE] = { 0 };
	u8   nb_scan_types = 0;
	bool tcp_scan = false, udp_scan = false;
	char *arg = strdup("SYN,");

	//TODO: comment on justifie ca ?
	/* strtok_r silently drops the trailing comma so "SYN," parses as
	 * "SYN".  This is intentionally different from parse_ports which
	 * rejects "80," (empty token).  The inconsistency is a known quirk
	 * of the two parsers; this test documents the current behaviour. */
	ASSERT(parse_scan_types(arg, &scan_types, &nb_scan_types, &tcp_scan, &udp_scan) == SUCCESS);
	ASSERT_EQ(1, nb_scan_types);
	ASSERT_EQ(SCAN_SYN, scan_types[0]);
	free(arg);
	PASS();
}


/* ------------------------------------------------------------------ */
/*  parse_args: invalid inputs (existing)                               */
/* ------------------------------------------------------------------ */

TEST parse_args_invalid_scan_returns_error(void)
{
	t_args args;
	char  *argv[] = { "ft_nmap", "--scan", "SYNN", NULL };
	int	   argc = 3;

	optind = 1;
	ASSERT(parse_args(argc, argv, &args, NULL, NULL) == FAILURE);
	PASS();
}

TEST parse_args_invalid_option(void)
{
	t_args args;
	char  *argv[] = { "ft_nmap", "--test", NULL };
	int	   argc = 2;

	optind = 1;
	ASSERT(parse_args(argc, argv, &args, NULL, NULL) == FAILURE);
	PASS();
}

/* ------------------------------------------------------------------ */
/*  parse_args: flags                                                   */
/* ------------------------------------------------------------------ */

TEST parse_args_sets_verbose_flag(void)
{
	t_args args = { 0 };
	char  *argv[] = { "ft_nmap", "--verbose", NULL };
	int    argc = 2;

	optind = 1;
	ASSERT(parse_args(argc, argv, &args, NULL, NULL) == SUCCESS);
	ASSERT(HAS(args.flags, F_VERBOSE));
	PASS();
}

TEST parse_args_sets_reason_flag(void)
{
	t_args args = { 0 };
	char  *argv[] = { "ft_nmap", "--reason", NULL };
	int    argc = 2;

	optind = 1;
	ASSERT(parse_args(argc, argv, &args, NULL, NULL) == SUCCESS);
	ASSERT(HAS(args.flags, F_REASON));
	PASS();
}

TEST parse_args_sets_packet_trace_flag(void)
{
	t_args args = { 0 };
	char  *argv[] = { "ft_nmap", "--packet-trace", NULL };
	int    argc = 2;

	optind = 1;
	ASSERT(parse_args(argc, argv, &args, NULL, NULL) == SUCCESS);
	ASSERT(HAS(args.flags, F_PACKET_TRACE));
	PASS();
}

TEST parse_args_sets_version_flag(void)
{
	t_args args = { 0 };
	char  *argv[] = { "ft_nmap", "--version", NULL };
	int    argc = 2;

	optind = 1;
	ASSERT(parse_args(argc, argv, &args, NULL, NULL) == SUCCESS);
	ASSERT(HAS(args.flags, F_VERSION));
	PASS();
}

/* ------------------------------------------------------------------ */
/*  parse_args: --speedup                                              */
/* ------------------------------------------------------------------ */

TEST parse_args_speedup_valid(void)
{
	t_args args = { 0 };
	char  *argv[] = { "ft_nmap", "--speedup", "10", NULL };
	int    argc = 3;

	optind = 1;
	ASSERT(parse_args(argc, argv, &args, NULL, NULL) == SUCCESS);
	ASSERT(HAS(args.flags, F_SPEED));
	ASSERT_EQ(10, args.speed);
	PASS();
}

TEST parse_args_speedup_zero(void)
{
	t_args args = { 0 };
	char  *argv[] = { "ft_nmap", "--speedup", "0", NULL };
	int    argc = 3;

	optind = 1;
	ASSERT(parse_args(argc, argv, &args, NULL, NULL) == SUCCESS);
	ASSERT(HAS(args.flags, F_SPEED));
	ASSERT_EQ(0, args.speed);
	PASS();
}

TEST parse_args_speedup_max(void)
{
	t_args args = { 0 };
	char  *argv[] = { "ft_nmap", "--speedup", "250", NULL };
	int    argc = 3;

	optind = 1;
	ASSERT(parse_args(argc, argv, &args, NULL, NULL) == SUCCESS);
	ASSERT(HAS(args.flags, F_SPEED));
	ASSERT_EQ(250, args.speed);
	PASS();
}

TEST parse_args_speedup_exceeds_max(void)
{
	t_args args = { 0 };
	char  *argv[] = { "ft_nmap", "--speedup", "251", NULL };
	int    argc = 3;

	optind = 1;
	ASSERT(parse_args(argc, argv, &args, NULL, NULL) == FAILURE);
	PASS();
}

TEST parse_args_speedup_invalid_string(void)
{
	t_args args = { 0 };
	char  *argv[] = { "ft_nmap", "--speedup", "abc", NULL };
	int    argc = 3;

	optind = 1;
	ASSERT(parse_args(argc, argv, &args, NULL, NULL) == FAILURE);
	PASS();
}

TEST parse_args_speedup_overflow(void)
{
	t_args args = { 0 };
	char  *argv[] = { "ft_nmap", "--speedup", "99999", NULL };
	int    argc = 3;

	/* Values far above SPEED_MAX must be rejected */
	optind = 1;
	ASSERT(parse_args(argc, argv, &args, NULL, NULL) == FAILURE);
	PASS();
}

TEST parse_args_rejects_positional_argument(void)
{
	t_args args = { 0 };
	char  *argv[] = { "ft_nmap", "unexpected_arg", NULL };
	int    argc = 2;

	/* Non-option arguments after options must be rejected */
	optind = 1;
	ASSERT(parse_args(argc, argv, &args, NULL, NULL) == FAILURE);
	PASS();
}


/* ------------------------------------------------------------------ */
/*  parse_args: --decoy                                                */
/* ------------------------------------------------------------------ */

TEST parse_args_decoy_single_ip(void)
{
	t_args args = { 0 };
	char  *argv[] = { "ft_nmap", "--decoy", "127.0.0.1", NULL };
	int    argc = 3;

	optind = 1;
	ASSERT(parse_args(argc, argv, &args, NULL, NULL) == SUCCESS);
	ASSERT(HAS(args.flags, F_DECOY));
	ASSERT_EQ(1, args.decoy_count);
	PASS();
}

TEST parse_args_decoy_multiple(void)
{
	t_args args = { 0 };
	char  *argv[] = { "ft_nmap", "--decoy", "127.0.0.1,127.0.0.2", NULL };
	int    argc = 3;

	optind = 1;
	ASSERT(parse_args(argc, argv, &args, NULL, NULL) == SUCCESS);
	ASSERT_EQ(2, args.decoy_count);
	PASS();
}

TEST parse_args_decoy_me_sentinel(void)
{
	t_args args = { 0 };
	char  *argv[] = { "ft_nmap", "--decoy", "ME", NULL };
	int    argc = 3;

	optind = 1;
	ASSERT(parse_args(argc, argv, &args, NULL, NULL) == SUCCESS);
	ASSERT_EQ(1, args.decoy_count);
	/* ME is stored as INADDR_ANY (0) as a sentinel for "our own IP" */
	ASSERT_EQ((in_addr_t)INADDR_ANY, args.decoys[0].s_addr);
	PASS();
}

TEST parse_args_decoy_too_many(void)
{
	t_args args = { 0 };
	/* MAX_DECOYS = 3, so 4 entries must be rejected */
	char  *argv[] = { "ft_nmap", "--decoy",
					  "127.0.0.1,127.0.0.2,127.0.0.3,127.0.0.4", NULL };
	int    argc = 3;

	optind = 1;
	ASSERT(parse_args(argc, argv, &args, NULL, NULL) == FAILURE);
	PASS();
}

TEST parse_args_decoy_invalid_ip(void)
{
	t_args args = { 0 };
	char  *argv[] = { "ft_nmap", "--decoy", "not_an_ip_address", NULL };
	int    argc = 3;

	optind = 1;
	ASSERT(parse_args(argc, argv, &args, NULL, NULL) == FAILURE);
	PASS();
}

/* ------------------------------------------------------------------ */
/*  parse_args: default values                                          */
/* ------------------------------------------------------------------ */

TEST parse_args_default_ports_fills_1_to_1024(void)
{
	t_args args = { 0 };
	/* No --ports: should auto-fill ports 1..1024 */
	char  *argv[] = { "ft_nmap", "--scan", "SYN", NULL };
	int    argc = 3;

	optind = 1;
	ASSERT(parse_args(argc, argv, &args, NULL, NULL) == SUCCESS);
	ASSERT_EQ(MAX_PORT_COUNT, args.port_count);
	ASSERT_EQ(1,    args.ports[0]);
	ASSERT_EQ(1024, args.ports[MAX_PORT_COUNT - 1]);
	PASS();
}

TEST parse_args_default_scan_uses_all_types(void)
{
	t_args args = { 0 };
	/* No --scan: should enable all 6 scan types */
	char  *argv[] = { "ft_nmap", "--ports", "80", NULL };
	int    argc = 3;

	optind = 1;
	ASSERT(parse_args(argc, argv, &args, NULL, NULL) == SUCCESS);
	ASSERT_EQ(MAX_NB_SCAN_TYPE, args.nb_scan_types);
	/* Verify each scan type value is present in the default set */
	ASSERT_EQ(SCAN_SYN,  args.scan_types[0]);
	ASSERT_EQ(SCAN_NULL, args.scan_types[1]);
	ASSERT_EQ(SCAN_ACK,  args.scan_types[2]);
	ASSERT_EQ(SCAN_FIN,  args.scan_types[3]);
	ASSERT_EQ(SCAN_XMAS, args.scan_types[4]);
	ASSERT_EQ(SCAN_UDP,  args.scan_types[5]);
	PASS();
}

/* ------------------------------------------------------------------ */
/*  parse_args: --file                                                  */
/* ------------------------------------------------------------------ */

TEST parse_args_file_valid(void)
{
	t_args  args = { 0 };
	char   *argv[] = { "ft_nmap", "--file", "/tmp/ft_nmap_test_targets.txt",
					  NULL };
	int     argc = 3;
	char  **targets = NULL;
	size_t  target_count = 0;

	/* Write a file with two IPs, one comment and one blank line */
	FILE *f = fopen("/tmp/ft_nmap_test_targets.txt", "w");
	if (!f)
		FAIL();
	fprintf(f, "127.0.0.1\n# this is a comment\n\n192.168.1.1\n");
	fclose(f);

	optind = 1;
	ASSERT(parse_args(argc, argv, &args, &targets, &target_count) == SUCCESS);
	ASSERT(HAS(args.flags, F_FILE_MODE));
	ASSERT_EQ(2, (int)target_count);
	ASSERT_STR_EQ("127.0.0.1",   targets[0]);
	ASSERT_STR_EQ("192.168.1.1", targets[1]);

	for (size_t i = 0; i < target_count; i++)
		free(targets[i]);
	free(targets);
	remove("/tmp/ft_nmap_test_targets.txt");
	PASS();
}

TEST parse_args_file_rejects_nonexistent(void)
{
	t_args  args = { 0 };
	char   *argv[] = { "ft_nmap", "--file", "/tmp/ft_nmap_no_such_file.txt",
					  NULL };
	int     argc = 3;

	optind = 1;
	ASSERT(parse_args(argc, argv, &args, NULL, NULL) == FAILURE);
	PASS();
}

TEST parse_args_file_rejects_empty(void)
{
	t_args  args = { 0 };
	char   *argv[] = { "ft_nmap", "--file", "/tmp/ft_nmap_empty.txt", NULL };
	int     argc = 3;

	/* An empty file (or one with only comments/blanks) must be rejected */
	FILE *f = fopen("/tmp/ft_nmap_empty.txt", "w");
	if (!f)
		FAIL();
	fclose(f);

	optind = 1;
	ASSERT(parse_args(argc, argv, &args, NULL, NULL) == FAILURE);
	remove("/tmp/ft_nmap_empty.txt");
	PASS();
}

TEST parse_args_file_and_ip_conflict(void)
{
	t_args  args = { 0 };
	char   *argv[] = { "ft_nmap", "--ip", "127.0.0.1",
					  "--file", "/tmp/ft_nmap_test_targets.txt", NULL };
	int     argc = 5;
	char  **targets = NULL;
	size_t  target_count = 0;

	/* Using --ip and --file together must be rejected */
	FILE *f = fopen("/tmp/ft_nmap_test_targets.txt", "w");
	if (!f)
		FAIL();
	fprintf(f, "127.0.0.1\n");
	fclose(f);

	optind = 1;
	ASSERT(parse_args(argc, argv, &args, NULL, NULL) == FAILURE);
	if (targets)
	{
		for (size_t i = 0; i < target_count; i++)
			free(targets[i]);
		free(targets);
	}
	remove("/tmp/ft_nmap_test_targets.txt");
	PASS();
}


/* ------------------------------------------------------------------ */
/*  Suite                                                               */
/* ------------------------------------------------------------------ */

SUITE(parse_ports_suite)
{
	RUN_TEST(parse_ports_parses_single_port);
	RUN_TEST(parse_ports_parses_multiple_port);
	RUN_TEST(parse_ports_parses_range);
	RUN_TEST(parse_ports_rejects_invalid_port);
	RUN_TEST(parse_ports_rejects_invalid_range);
	RUN_TEST(parse_ports_accepts_port_zero);
	RUN_TEST(parse_ports_accepts_max_port);
	RUN_TEST(parse_ports_rejects_out_of_range);
	RUN_TEST(parse_ports_ignores_duplicate);
	RUN_TEST(parse_ports_accepts_multiple_ranges);
	RUN_TEST(parse_ports_rejects_range_too_large);
	RUN_TEST(parse_ports_rejects_reversed_range);
	RUN_TEST(parse_ports_accepts_extra_commas);
	RUN_TEST(parse_ports_rejects_double_dash);
}

SUITE(parse_scan_types_suite)
{
	RUN_TEST(parse_args_parses_scan_types);
	RUN_TEST(parse_scan_types_all_types);
	RUN_TEST(parse_scan_types_rejects_duplicate);
	RUN_TEST(parse_scan_types_case_insensitive);
	RUN_TEST(parse_scan_types_rejects_empty_string);
	RUN_TEST(parse_scan_types_accepts_trailing_comma);
}

SUITE(parse_args_suite)
{
	/* invalid inputs */
	RUN_TEST(parse_args_invalid_option);
	RUN_TEST(parse_args_rejects_positional_argument);
	RUN_TEST(parse_args_invalid_scan_returns_error);

	/* flags */
	RUN_TEST(parse_args_sets_verbose_flag);
	RUN_TEST(parse_args_sets_reason_flag);
	RUN_TEST(parse_args_sets_packet_trace_flag);
	RUN_TEST(parse_args_sets_version_flag);

	/* --speedup */
	RUN_TEST(parse_args_speedup_valid);
	RUN_TEST(parse_args_speedup_zero);
	RUN_TEST(parse_args_speedup_max);
	RUN_TEST(parse_args_speedup_exceeds_max);
	RUN_TEST(parse_args_speedup_invalid_string);
	RUN_TEST(parse_args_speedup_overflow);

	/* --decoy */
	RUN_TEST(parse_args_decoy_single_ip);
	RUN_TEST(parse_args_decoy_multiple);
	RUN_TEST(parse_args_decoy_me_sentinel);
	RUN_TEST(parse_args_decoy_too_many);
	RUN_TEST(parse_args_decoy_invalid_ip);

	/* default values */
	RUN_TEST(parse_args_default_ports_fills_1_to_1024);
	RUN_TEST(parse_args_default_scan_uses_all_types);

	/* --file */
	RUN_TEST(parse_args_file_valid);
	RUN_TEST(parse_args_file_rejects_nonexistent);
	RUN_TEST(parse_args_file_rejects_empty);
	RUN_TEST(parse_args_file_and_ip_conflict);
}
