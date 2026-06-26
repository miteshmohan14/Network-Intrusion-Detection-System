#include "traffic_statistics.h"
#include "packet_structures.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <iostream>
#include <unordered_map>
#include <chrono>
#include <string>

using namespace std;
using namespace std::chrono;

static uint64_t totalPackets = 0;
static uint64_t totalBytes = 0;

static uint64_t tcpPackets = 0;
static uint64_t udpPackets = 0;
static uint64_t icmpPackets = 0;
static uint64_t otherPackets = 0;

static unordered_map<string, uint64_t> sourceTraffic;

static steady_clock::time_point startTime =
    steady_clock::now();

const int REPORT_INTERVAL = 30;   // seconds

void printStatistics()
{
    cout << "\n==============================================" << endl;
    cout << "         NETWORK TRAFFIC STATISTICS" << endl;
    cout << "==============================================" << endl;

    cout << "Total Packets : " << totalPackets << endl;
    cout << "Total Bytes   : " << totalBytes << endl;

    cout << "\nProtocol Distribution" << endl;
    cout << "TCP   : " << tcpPackets << endl;
    cout << "UDP   : " << udpPackets << endl;
    cout << "ICMP  : " << icmpPackets << endl;
    cout << "Other : " << otherPackets << endl;

    cout << "\nTop Source IPs" << endl;

    int count = 0;

    for (const auto& entry : sourceTraffic)
    {
        cout << entry.first
             << " -> "
             << entry.second
             << " packets"
             << endl;

        if (++count >= 10)
            break;
    }

    cout << "==============================================\n"
         << endl;
}

void updateTrafficStats(
    const u_char* packet,
    const pcap_pkthdr* header)
{
    totalPackets++;
    totalBytes += header->len;

    const EthernetHeader* eth =
        (const EthernetHeader*)packet;

    if (ntohs(eth->type) != 0x0800)
    {
        otherPackets++;
        return;
    }

    const IPHeader* ip =
        (const IPHeader*)(packet + sizeof(EthernetHeader));

    string srcIP =
        inet_ntoa(*(in_addr*)&ip->src_ip);

    sourceTraffic[srcIP]++;

    switch (ip->protocol)
    {
        case IPPROTO_TCP:
            tcpPackets++;
            break;

        case IPPROTO_UDP:
            udpPackets++;
            break;

        case IPPROTO_ICMP:
            icmpPackets++;
            break;

        default:
            otherPackets++;
            break;
    }

    auto now = steady_clock::now();

    auto elapsed =
        duration_cast<seconds>(
            now - startTime).count();

    if (elapsed >= REPORT_INTERVAL)
    {
        printStatistics();
        startTime = now;
    }
}