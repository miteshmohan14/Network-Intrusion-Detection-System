#include "syn_flood_detector.h"
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

struct SynInfo
{
    int count;
    steady_clock::time_point start;
};

static unordered_map<string, SynInfo> synTable;

const int SYN_THRESHOLD = 100;
const int TIME_WINDOW = 10;

void detectSynFlood(
    const u_char* packet,
    const pcap_pkthdr* header)
{
    const EthernetHeader* eth =
        (EthernetHeader*)packet;

    if (ntohs(eth->type) != 0x0800)
        return;

    const IPHeader* ip =
        (IPHeader*)(packet + sizeof(EthernetHeader));

    if (ip->protocol != IPPROTO_TCP)
        return;

    const TCPHeader* tcp =
        (TCPHeader*)
        ((u_char*)ip + ((ip->ver_ihl & 0x0F) * 4));

    // SYN set, ACK not set
    if ((tcp->flags & 0x02) && !(tcp->flags & 0x10))
    {
        string srcIP = inet_ntoa(*(in_addr*)&ip->src_ip);

        auto now = steady_clock::now();

        if (synTable.find(srcIP) == synTable.end())
        {
            synTable[srcIP] = {1, now};
            return;
        }

        auto elapsed =
            duration_cast<seconds>(
                now - synTable[srcIP].start).count();

        if (elapsed > TIME_WINDOW)
        {
            synTable[srcIP].count = 1;
            synTable[srcIP].start = now;
            return;
        }

        synTable[srcIP].count++;

        if (synTable[srcIP].count >= SYN_THRESHOLD)
        {
            cout << endl;
            cout << "======================================" << endl;
            cout << "[ALERT] SYN Flood Detected" << endl;
            cout << "Source IP : " << srcIP << endl;
            cout << "Packets   : "
                 << synTable[srcIP].count << endl;
            cout << "======================================" << endl;

            logAlert(
                "SYN Flood detected from " +
                srcIP);

            synTable[srcIP].count = 0;
            synTable[srcIP].start = now;
        }
    }
}