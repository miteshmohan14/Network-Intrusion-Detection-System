#pragma once

#include <pcap.h>

void detectPortScan(
    const u_char* packet,
    const pcap_pkthdr* header);