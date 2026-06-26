#pragma once

#include <pcap.h>

void detectProtocol(
    const u_char* packet,
    const pcap_pkthdr* header);