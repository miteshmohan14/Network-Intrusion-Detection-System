#include "icmp_flood_detector.h"
#include "packet_structures.h"
#include "logger.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <iostream>
#include <unordered_map>
#include <chrono>
#include <string>

using namespace std;
using namespace std::chrono;

#pragma pack(push,1)

struct ICMPHeader
{
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
    unsigned short identifier;
    unsigned short sequence;
};

#pragma pack(pop)

struct ICMPStats
{
    int packetCount;
    steady_clock::time_point startTime;
};

static unordered_map<string, ICMPStats> icmpTable;

const int ICMP_THRESHOLD = 100;
const int TIME_WINDOW = 5;

void detectICMPFlood(
    const u_char* packet,
    const pcap_pkthdr* header)
{
    const EthernetHeader* eth =
        (const EthernetHeader*)packet;

    // IPv4 only
    if (ntohs(eth->type) != 0x0800)
        return;

    const IPHeader* ip =
        (const IPHeader*)(packet + sizeof(EthernetHeader));

    // ICMP only
    if (ip->protocol != IPPROTO_ICMP)
        return;

    int ipHeaderLength =
        (ip->ver_ihl & 0x0F) * 4;

    const ICMPHeader* icmp =
        (const ICMPHeader*)
        ((const u_char*)ip + ipHeaderLength);

    string srcIP =
        inet_ntoa(*(in_addr*)&ip->src_ip);

    auto now = steady_clock::now();

    if (icmpTable.find(srcIP) == icmpTable.end())
    {
        icmpTable[srcIP] = {1, now};
        return;
    }

    auto elapsed =
        duration_cast<seconds>(
            now - icmpTable[srcIP].startTime).count();

    if (elapsed > TIME_WINDOW)
    {
        icmpTable[srcIP].packetCount = 1;
        icmpTable[srcIP].startTime = now;
        return;
    }

    icmpTable[srcIP].packetCount++;

    // Detect Echo Request Flood
    if (icmp->type == 8 &&
        icmpTable[srcIP].packetCount >= ICMP_THRESHOLD)
    {
        cout << endl;
        cout << "==========================================" << endl;
        cout << "[ALERT] ICMP Flood Detected" << endl;
        cout << "Source IP : " << srcIP << endl;
        cout << "Packets   : "
             << icmpTable[srcIP].packetCount << endl;
        cout << "Window    : "
             << TIME_WINDOW
             << " seconds" << endl;
        cout << "==========================================" << endl;

        logAlert(
            "ICMP Flood detected from " +
            srcIP);

        icmpTable[srcIP].packetCount = 0;
        icmpTable[srcIP].startTime = now;
    }
}