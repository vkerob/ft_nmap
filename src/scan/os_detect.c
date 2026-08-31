#include "scan.h"

/*
** OS detection based on IP TTL and TCP window size from SYN-ACK responses.
**
** Strategy:
**   1. Normalise the observed TTL to the most likely initial TTL:
**        TTL in [1..64]   → initial TTL was 64  → Linux / macOS / BSD
**        TTL in [65..128] → initial TTL was 128 → Windows
**        TTL in [129..255]→ initial TTL was 255 → Cisco / network device
**
**   2. For the Linux/macOS family, use the TCP window size to narrow down:
**        65535           → macOS / FreeBSD / iOS
**        29200 / 64240   → Linux (common on Ubuntu/Debian)
**        otherwise       → Linux (generic)
**
**   3. For Windows, optionally refine with window:
**        8192            → Windows (older / default)
**        65535           → Windows 10/11 (with window scaling)
**
*/

const char *guess_os(u8 ttl, u16 tcp_window)
{
	if (ttl == 0)
		return "Unknown (no response captured)";

	/* --- Cisco / network device --- */
	if (ttl > 128)
		return "Cisco / Network device (TTL > 128)";

	/* --- Windows --- */
	if (ttl > 64)
	{
		if (tcp_window == 8192)
			return "Windows (TTL=128, win=8192)";
		if (tcp_window == 65535)
			return "Windows 10/11 (TTL=128, win=65535)";
		return "Windows (TTL=128)";
	}

	/* --- Linux / macOS / BSD (TTL <= 64) --- */
	if (tcp_window == 65535)
		return "macOS / FreeBSD (TTL=64, win=65535)";
	if (tcp_window == 29200 || tcp_window == 64240 || tcp_window == 65160)
		return "Linux (TTL=64)";
	if (tcp_window == 5840 || tcp_window == 14600)
		return "Linux older kernel (TTL=64)";

	return "Linux / macOS (TTL=64)";
}
