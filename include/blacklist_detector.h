#pragma once

#include <pcap.h>

void loadBlacklist();

void detectBlacklistIP(
    const u_char* packet,
    const pcap_pkthdr* header);