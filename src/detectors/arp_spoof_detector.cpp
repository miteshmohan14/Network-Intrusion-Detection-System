#include "arp_spoof_detector.h"
#include "packet_structures.h"
#include "logger.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <iostream>
#include <iomanip>
#include <unordered_map>
#include <sstream>
#include <string>

using namespace std;

struct ARPHeader
{
    unsigned short hardwareType;
    unsigned short protocolType;
    unsigned char hardwareSize;
    unsigned char protocolSize;
    unsigned short opcode;

    unsigned char senderMAC[6];
    unsigned int senderIP;

    unsigned char targetMAC[6];
    unsigned int targetIP;
};

static unordered_map<string, string> arpTable;

string macToString(const unsigned char* mac)
{
    stringstream ss;

    ss << hex
       << setw(2) << setfill('0') << (int)mac[0] << ":"
       << setw(2) << setfill('0') << (int)mac[1] << ":"
       << setw(2) << setfill('0') << (int)mac[2] << ":"
       << setw(2) << setfill('0') << (int)mac[3] << ":"
       << setw(2) << setfill('0') << (int)mac[4] << ":"
       << setw(2) << setfill('0') << (int)mac[5];

    return ss.str();
}

string ipToString(unsigned int ip)
{
    in_addr addr;
    addr.s_addr = ip;

    return string(inet_ntoa(addr));
}

void detectArpSpoof(
    const u_char* packet,
    const pcap_pkthdr* header)
{
    const EthernetHeader* eth =
        (const EthernetHeader*)packet;

    // Ethernet type 0x0806 = ARP
    if (ntohs(eth->type) != 0x0806)
        return;

    const ARPHeader* arp =
        (const ARPHeader*)
        (packet + sizeof(EthernetHeader));

    string ip = ipToString(arp->senderIP);
    string mac = macToString(arp->senderMAC);

    auto it = arpTable.find(ip);

    if (it == arpTable.end())
    {
        arpTable[ip] = mac;
        return;
    }

    if (it->second != mac)
    {
        cout << "\n=====================================\n";
        cout << "[ALERT] ARP Spoofing Detected\n";
        cout << "IP Address : " << ip << endl;
        cout << "Old MAC    : " << it->second << endl;
        cout << "New MAC    : " << mac << endl;
        cout << "=====================================\n";

        logAlert(
            "ARP Spoofing detected from " +
            ip +
            " (Old MAC: " +
            it->second +
            ", New MAC: " +
            mac +
            ")");

        arpTable[ip] = mac;
    }
}