#include "anomaly_detector.h"
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

struct TrafficInfo
{
    int packetCount;
    steady_clock::time_point startTime;
};

static unordered_map<string, TrafficInfo> trafficTable;

const int PACKET_THRESHOLD = 500;
const int TIME_WINDOW = 5;

void detectAnomaly(
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

    string srcIP = inet_ntoa(*(in_addr*)&ip->src_ip);

    auto now = steady_clock::now();

    if (trafficTable.find(srcIP) == trafficTable.end())
    {
        trafficTable[srcIP] = {1, now};
        return;
    }

    auto elapsed =
        duration_cast<seconds>(
            now - trafficTable[srcIP].startTime).count();

    if (elapsed > TIME_WINDOW)
    {
        trafficTable[srcIP].packetCount = 1;
        trafficTable[srcIP].startTime = now;
        return;
    }

    trafficTable[srcIP].packetCount++;

    if (trafficTable[srcIP].packetCount >= PACKET_THRESHOLD)
    {
        cout << endl;
        cout << "=========================================" << endl;
        cout << "[ALERT] Traffic Anomaly Detected" << endl;
        cout << "Source IP : " << srcIP << endl;
        cout << "Packets   : "
             << trafficTable[srcIP].packetCount << endl;
        cout << "Time      : "
             << TIME_WINDOW << " seconds" << endl;
        cout << "=========================================" << endl;

        logAlert(
            "Traffic anomaly detected from " +
            srcIP);

        trafficTable[srcIP].packetCount = 0;
        trafficTable[srcIP].startTime = now;
    }
}