/* ===========================================================================
 * Public interface of the module holding the data ft_nmap takes from Nmap:
 * the UDP probe payloads (payloads.c) and the port-to-service name tables
 * (port_services.c).
 *
 * That data comes from the Nmap Security Scanner -- https://nmap.org --
 * Copyright (c) 1996-2026 Nmap Software LLC ("The Nmap Project"), and is used
 * under the Nmap Public Source License Version 0.95. The complete text of
 * that license, Exhibit A included, is in the LICENSE file at the root of
 * this repository.
 *
 * Notice of modification, as required by section 2a of the GPL Version 2
 * incorporated by the NPSL as Exhibit A:
 *
 *     Modified 2026-09-18 by vkerob and damienglld. See the header of
 *     payloads.c and port_services.c for what was changed.
 *
 * ft_nmap is not affiliated with, endorsed by, or a product of the Nmap
 * Project. "Nmap" is a trademark of Nmap Software LLC and is used here only
 * to describe the origin of this data.
 *
 * This header deliberately depends on nothing else in ft_nmap, and nothing
 * else in ft_nmap touches that data directly: the three functions below are
 * the only way in. Dropping this module means deleting src/payloads/ and the
 * calls to those functions.
 * ========================================================================= */

#ifndef PAYLOADS_H
#define PAYLOADS_H

#include <stddef.h>
#include <stdint.h>

/* Longest payload list a single port can be probed with. */
#define MAX_UDP_PAYLOADS_PER_PORT 8

typedef struct s_udp_probe_payload
{
	const uint8_t *data;
	size_t		   len;
} t_udp_probe_payload;

/* Fills `out` with up to `max` payloads registered for `dest_port` and
 * returns how many were written. Narrower port ranges come first, so the
 * most specific probe for a port is also the first one returned. */
size_t get_udp_payloads(uint16_t dest_port, t_udp_probe_payload *out,
						size_t max);

/* Service usually found on `port`, or "unknown" when nmap-services lists
 * none. The returned string is static storage: it is never freed and stays
 * valid for the lifetime of the program. */
const char *get_tcp_service(uint16_t port);
const char *get_udp_service(uint16_t port);

#endif
