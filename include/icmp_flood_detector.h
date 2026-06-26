#pragma once

#include <pcap.h>

void detectICMPFlood(
    const u_char* packet,
    const pcap_pkthdr* header);