#pragma once

#include <pcap.h>

void detectArpSpoof(
    const u_char* packet,
    const pcap_pkthdr* header);