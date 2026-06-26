#pragma once

#include <pcap.h>

void monitorHTTP(
    const u_char* packet,
    const pcap_pkthdr* header);