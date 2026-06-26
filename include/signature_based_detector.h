#pragma once

#include <pcap.h>

void detectSignatures(
    const u_char* packet,
    const pcap_pkthdr* header);