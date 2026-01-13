#ifndef COMPAT_PCAP_H
#define COMPAT_PCAP_H

#if __has_include(<pcap/pcap.h>)
#include <pcap/pcap.h>
#elif __has_include(<pcap.h>)
#include <pcap.h>
#else
#error "pcap.h not found"
#endif

#endif // COMPAT_PCAP_H