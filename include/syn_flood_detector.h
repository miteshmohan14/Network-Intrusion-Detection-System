#pragma once

#include <pcap.h>

void detectSynFlood(
    const u_char* packet,
    const pcap_pkthdr* header);