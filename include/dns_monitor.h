#pragma once

#include <pcap.h>

void monitorDNS(
    const u_char* packet,
    const pcap_pkthdr* header);