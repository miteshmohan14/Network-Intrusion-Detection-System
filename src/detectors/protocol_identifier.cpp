#include "protocol_identifier.h"
#include "packet_structures.h"
#include "logger.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>

using namespace std;

// Returns protocol/service name based on port
string getProtocolName(unsigned short port)
{
    switch (port)
    {
        case 20:
        case 21: return "FTP";

        case 22: return "SSH";

        case 23: return "TELNET";

        case 25: return "SMTP";

        case 53: return "DNS";

        case 67:
        case 68: return "DHCP";

        case 80: return "HTTP";

        case 110: return "POP3";

        case 123: return "NTP";

        case 143: return "IMAP";

        case 443: return "HTTPS";

        case 3306: return "MySQL";

        case 3389: return "RDP";

        case 8009: return "Google Cast";

        case 8080: return "HTTP-ALT";

        default:
            return "UNKNOWN";
    }
}

void detectProtocol(
    const u_char* packet,
    const pcap_pkthdr* header)
{
    const EthernetHeader* eth =
        (EthernetHeader*)packet;

    // Only IPv4
    if (ntohs(eth->type) != 0x0800)
        return;

    const IPHeader* ip =
        (IPHeader*)(packet + sizeof(EthernetHeader));

    string srcIP = inet_ntoa(*(in_addr*)&ip->src_ip);
    string dstIP = inet_ntoa(*(in_addr*)&ip->dest_ip);

    string protocol = "UNKNOWN";
    string flags = "";

    if (ip->protocol == IPPROTO_TCP)
    {
        const TCPHeader* tcp =
            (TCPHeader*)((u_char*)ip +
            ((ip->ver_ihl & 0x0F) * 4));

        unsigned short srcPort = ntohs(tcp->src_port);
        unsigned short dstPort = ntohs(tcp->dst_port);

        protocol = getProtocolName(dstPort);

        if (tcp->flags & 0x02) flags += "[SYN] ";
        if (tcp->flags & 0x10) flags += "[ACK] ";
        if (tcp->flags & 0x01) flags += "[FIN] ";
        if (tcp->flags & 0x04) flags += "[RST] ";
        if (tcp->flags & 0x08) flags += "[PSH] ";
        if (tcp->flags & 0x20) flags += "[URG] ";

        cout << srcIP << ":" << srcPort
             << " -> "
             << dstIP << ":" << dstPort
             << " | "
             << protocol
             << " "
             << flags
             << endl;
    }
    else if (ip->protocol == IPPROTO_UDP)
    {
        const UDPHeader* udp =
            (UDPHeader*)((u_char*)ip +
            ((ip->ver_ihl & 0x0F) * 4));

        unsigned short srcPort = ntohs(udp->src_port);
        unsigned short dstPort = ntohs(udp->dst_port);

        protocol = getProtocolName(dstPort);

        cout << srcIP << ":" << srcPort
             << " -> "
             << dstIP << ":" << dstPort
             << " | "
             << protocol
             << " (UDP)"
             << endl;
    }
    else if (ip->protocol == IPPROTO_ICMP)
    {
        cout << srcIP
             << " -> "
             << dstIP
             << " | ICMP"
             << endl;
    }
}