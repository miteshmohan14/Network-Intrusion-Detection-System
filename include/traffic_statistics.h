#pragma once

#include <pcap.h>

void updateTrafficStats(
    const u_char* packet,
    const pcap_pkthdr* header);