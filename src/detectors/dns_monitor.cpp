#include "dns_monitor.h"
#include "packet_structures.h"
#include "logger.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <iostream>
#include <vector>
#include <string>
#include <algorithm>

using namespace std;

#pragma pack(push,1)

struct DNSHeader
{
    unsigned short id;
    unsigned short flags;
    unsigned short questions;
    unsigned short answers;
    unsigned short authority;
    unsigned short additional;
};

#pragma pack(pop)

static vector<string> suspiciousDomains =
{
    "malware.com",
    "phishing.com",
    "evil.com",
    "badhost.net",
    "virus.org"
};

string extractDomain(const unsigned char* dnsQuery)
{
    string domain;

    int pos = 0;

    while (dnsQuery[pos] != 0)
    {
        int length = dnsQuery[pos++];

        if (length <= 0)
            break;

        for (int i = 0; i < length; i++)
        {
            domain += dnsQuery[pos++];
        }

        domain += '.';
    }

    if (!domain.empty())
        domain.pop_back();

    return domain;
}

bool isSuspicious(const string& domain)
{
    for (const auto& bad : suspiciousDomains)
    {
        if (domain.find(bad) != string::npos)
            return true;
    }

    return false;
}

void monitorDNS(
    const u_char* packet,
    const pcap_pkthdr* header)
{
    const EthernetHeader* eth =
        (const EthernetHeader*)packet;

    if (ntohs(eth->type) != 0x0800)
        return;

    const IPHeader* ip =
        (const IPHeader*)(packet + sizeof(EthernetHeader));

    if (ip->protocol != IPPROTO_UDP)
        return;

    int ipHeaderLength =
        (ip->ver_ihl & 0x0F) * 4;

    const UDPHeader* udp =
        (const UDPHeader*)
        ((const u_char*)ip + ipHeaderLength);

    unsigned short srcPort =
        ntohs(udp->src_port);

    unsigned short dstPort =
        ntohs(udp->dst_port);

    if (srcPort != 53 && dstPort != 53)
        return;

    const unsigned char* dnsData =
        (const unsigned char*)udp +
        sizeof(UDPHeader);

    const DNSHeader* dns =
        (const DNSHeader*)dnsData;

    if (ntohs(dns->questions) == 0)
        return;

    const unsigned char* query =
        dnsData + sizeof(DNSHeader);

    string domain =
        extractDomain(query);

    string srcIP =
        inet_ntoa(*(in_addr*)&ip->src_ip);

    string dstIP =
        inet_ntoa(*(in_addr*)&ip->dest_ip);

    cout << "[DNS] "
         << srcIP
         << " -> "
         << dstIP
         << " : "
         << domain
         << endl;

    logAlert(
        "DNS Query: " +
        srcIP +
        " -> " +
        domain);

    if (isSuspicious(domain))
    {
        cout << endl;
        cout << "======================================" << endl;
        cout << "[ALERT] Suspicious DNS Request" << endl;
        cout << "Source IP : " << srcIP << endl;
        cout << "Domain    : " << domain << endl;
        cout << "======================================" << endl;

        logAlert(
            "Suspicious DNS query detected: " +
            domain +
            " from " +
            srcIP);
    }
}