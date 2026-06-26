#pragma once

#include <pcap.h>

void loadRules();

void detectRuleMatch(
    const u_char* packet,
    const pcap_pkthdr* header);