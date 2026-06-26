#pragma once

#include <pcap.h>

void detectAnomaly(
    const u_char* packet,
    const pcap_pkthdr* header);