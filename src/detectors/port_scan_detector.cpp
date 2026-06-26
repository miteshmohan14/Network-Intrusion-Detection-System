#include "port_scan_detector.h"
#include "packet_structures.h"
#include "logger.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <string>

using namespace std;
using namespace std::chrono;

struct ScanInfo
{
    unordered_set<unsigned short> ports;
    steady_clock::time_point startTime;
};

static unordered_map<string, ScanInfo> scanTable;

const int PORT_SCAN_THRESHOLD = 20;
const int TIME_WINDOW = 10;

void detectPortScan(
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

    // TCP only
    if (ip->protocol != IPPROTO_TCP)
        return;

    int ipHeaderLength =
        (ip->ver_ihl & 0x0F) * 4;

    const TCPHeader* tcp =
        (const TCPHeader*)
        ((const u_char*)ip + ipHeaderLength);

    // Only SYN packets (ignore established traffic)
    if (!(tcp->flags & 0x02) || (tcp->flags & 0x10))
        return;

    unsigned short dstPort =
        ntohs(tcp->dst_port);

    string srcIP =
        inet_ntoa(*(in_addr*)&ip->src_ip);

    auto now = steady_clock::now();

    if (scanTable.find(srcIP) == scanTable.end())
    {
        ScanInfo info;
        info.startTime = now;
        info.ports.insert(dstPort);

        scanTable[srcIP] = info;
        return;
    }

    auto elapsed =
        duration_cast<seconds>(
            now - scanTable[srcIP].startTime).count();

    if (elapsed > TIME_WINDOW)
    {
        scanTable[srcIP].ports.clear();
        scanTable[srcIP].ports.insert(dstPort);
        scanTable[srcIP].startTime = now;
        return;
    }

    scanTable[srcIP].ports.insert(dstPort);

    if (scanTable[srcIP].ports.size() >= PORT_SCAN_THRESHOLD)
    {
        cout << endl;
        cout << "==========================================" << endl;
        cout << "[ALERT] Port Scan Detected" << endl;
        cout << "Source IP      : " << srcIP << endl;
        cout << "Unique Ports   : "
             << scanTable[srcIP].ports.size() << endl;
        cout << "Time Window    : "
             << TIME_WINDOW
             << " seconds" << endl;
        cout << "==========================================" << endl;

        logAlert(
            "Port Scan detected from " +
            srcIP +
            " (" +
            to_string(scanTable[srcIP].ports.size()) +
            " unique ports)");

        scanTable[srcIP].ports.clear();
        scanTable[srcIP].startTime = now;
    }
}