#include "blacklist_detector.h"
#include "packet_structures.h"
#include "logger.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <iostream>
#include <fstream>
#include <unordered_set>
#include <string>

using namespace std;

static unordered_set<string> blacklist;

void loadBlacklist()
{
    ifstream file("blacklist.txt");

    if (!file.is_open())
    {
        cout << "[Blacklist] blacklist.txt not found." << endl;
        return;
    }

    string ip;

    while (getline(file, ip))
    {
        if (!ip.empty())
            blacklist.insert(ip);
    }

    file.close();

    cout << "[Blacklist] Loaded "
         << blacklist.size()
         << " IP addresses."
         << endl;
}

void detectBlacklistIP(
    const u_char* packet,
    const pcap_pkthdr* header)
{
    const EthernetHeader* eth =
        (const EthernetHeader*)packet;

    if (ntohs(eth->type) != 0x0800)
        return;

    const IPHeader* ip =
        (const IPHeader*)(packet + sizeof(EthernetHeader));

    string srcIP =
        inet_ntoa(*(in_addr*)&ip->src_ip);

    string dstIP =
        inet_ntoa(*(in_addr*)&ip->dest_ip);

    if (blacklist.count(srcIP))
    {
        cout << endl;
        cout << "===================================" << endl;
        cout << "[ALERT] Blacklisted Source IP" << endl;
        cout << "Source : " << srcIP << endl;
        cout << "===================================" << endl;

        logAlert(
            "Blacklisted source IP detected: " +
            srcIP);
    }

    if (blacklist.count(dstIP))
    {
        cout << endl;
        cout << "===================================" << endl;
        cout << "[ALERT] Blacklisted Destination IP" << endl;
        cout << "Destination : " << dstIP << endl;
        cout << "===================================" << endl;

        logAlert(
            "Blacklisted destination IP detected: " +
            dstIP);
    }
}