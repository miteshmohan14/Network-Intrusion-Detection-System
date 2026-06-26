#include "rule_engine.h"
#include "packet_structures.h"
#include "logger.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include <string>

using namespace std;

struct Rule
{
    string protocol;
    string ip;
    int port;
    string action;
};

static vector<Rule> rules;

void loadRules()
{
    rules.clear();

    ifstream file("rules.txt");

    if (!file.is_open())
    {
        cout << "[Rule Engine] rules.txt not found." << endl;
        return;
    }

    string line;

    while (getline(file, line))
    {
        if (line.empty() || line[0] == '#')
            continue;

        stringstream ss(line);

        Rule r;

        ss >> r.protocol
           >> r.ip
           >> r.port
           >> r.action;

        if (!ss.fail())
            rules.push_back(r);
    }

    cout << "[Rule Engine] Loaded "
         << rules.size()
         << " rules."
         << endl;
}

void detectRuleMatch(
    const u_char* packet,
    const pcap_pkthdr* header)
{
    if (rules.empty())
        return;

    const EthernetHeader* eth =
        (const EthernetHeader*)packet;

    if (ntohs(eth->type) != 0x0800)
        return;

    const IPHeader* ip =
        (const IPHeader*)
        (packet + sizeof(EthernetHeader));

    string srcIP =
        inet_ntoa(*(in_addr*)&ip->src_ip);

    string dstIP =
        inet_ntoa(*(in_addr*)&ip->dest_ip);

    string protocol;
    int port = 0;

    if (ip->protocol == IPPROTO_TCP)
    {
        protocol = "TCP";

        const TCPHeader* tcp =
            (const TCPHeader*)
            ((const u_char*)ip +
            ((ip->ver_ihl & 0x0F) * 4));

        port = ntohs(tcp->dst_port);
    }
    else if (ip->protocol == IPPROTO_UDP)
    {
        protocol = "UDP";

        const UDPHeader* udp =
            (const UDPHeader*)
            ((const u_char*)ip +
            ((ip->ver_ihl & 0x0F) * 4));

        port = ntohs(udp->dst_port);
    }
    else if (ip->protocol == IPPROTO_ICMP)
    {
        protocol = "ICMP";
    }
    else
    {
        return;
    }

    for (const Rule& r : rules)
    {
        bool protocolMatch =
            (r.protocol == "*" ||
             r.protocol == protocol);

        bool ipMatch =
            (r.ip == "*" ||
             r.ip == srcIP ||
             r.ip == dstIP);

        bool portMatch =
            (r.port == -1 ||
             r.port == port);

        if (protocolMatch &&
            ipMatch &&
            portMatch)
        {
            cout << endl;
            cout << "======================================" << endl;
            cout << "[RULE MATCH]" << endl;
            cout << "Protocol : " << protocol << endl;
            cout << "Source   : " << srcIP << endl;
            cout << "Dest     : " << dstIP << endl;
            cout << "Port     : " << port << endl;
            cout << "Action   : " << r.action << endl;
            cout << "======================================" << endl;

            logAlert(
                "Rule matched -> " +
                protocol +
                " " +
                srcIP +
                ":" +
                to_string(port) +
                " Action: " +
                r.action);
        }
    }
}