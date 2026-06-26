#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <iostream>

using namespace std;

#pragma pack(push,1)

struct EthernetHeader
{
    unsigned char dest[6];
    unsigned char src[6];
    unsigned short type;
};

struct IPHeader
{
    unsigned char ver_ihl;
    unsigned char tos;
    unsigned short total_length;
    unsigned short identification;
    unsigned short flags_fragment;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    unsigned int src_ip;
    unsigned int dest_ip;
};

struct TCPHeader
{
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int seq_num;
    unsigned int ack_num;
    unsigned char data_offset;
    unsigned char flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_ptr;
};

struct UDPHeader
{
    unsigned short src_port;
    unsigned short dst_port;
    unsigned short length;
    unsigned short checksum;
};

#pragma pack(pop)

string getProtocolName(unsigned char protocol)
{
    switch(protocol)
    {
        case 1:
            return "ICMP";

        case 6:
            return "TCP";

        case 17:
            return "UDP";

        default:
            return "OTHER";
    }
}

void packetHandler(
    u_char*,
    const struct pcap_pkthdr* header,
    const u_char* packet)
{
    EthernetHeader* eth =
        (EthernetHeader*)packet;

    if(ntohs(eth->type) != 0x0800)
        return;

    IPHeader* ip =
        (IPHeader*)
        (packet + sizeof(EthernetHeader));

    char srcIp[INET_ADDRSTRLEN];
    char dstIp[INET_ADDRSTRLEN];

    in_addr src,dst;

    src.S_un.S_addr = ip->src_ip;
    dst.S_un.S_addr = ip->dest_ip;

    InetNtopA(
        AF_INET,
        &src,
        srcIp,
        INET_ADDRSTRLEN);

    InetNtopA(
        AF_INET,
        &dst,
        dstIp,
        INET_ADDRSTRLEN);

    int ipHeaderLength =
        (ip->ver_ihl & 0x0F) * 4;

    cout << "\n===================================" << endl;

    cout
        << "Source IP      : "
        << srcIp
        << endl;

    cout
        << "Destination IP : "
        << dstIp
        << endl;

    cout
        << "Protocol       : "
        << getProtocolName(ip->protocol)
        << endl;

    if(ip->protocol == 6)
    {
        TCPHeader* tcp =
            (TCPHeader*)
            (packet
            + sizeof(EthernetHeader)
            + ipHeaderLength);

        cout
            << "Source Port    : "
            << ntohs(tcp->src_port)
            << endl;

        cout
            << "Destination Port : "
            << ntohs(tcp->dst_port)
            << endl;
    }

    else if(ip->protocol == 17)
    {
        UDPHeader* udp =
            (UDPHeader*)
            (packet
            + sizeof(EthernetHeader)
            + ipHeaderLength);

        cout
            << "Source Port    : "
            << ntohs(udp->src_port)
            << endl;

        cout
            << "Destination Port : "
            << ntohs(udp->dst_port)
            << endl;
    }

    cout
        << "Packet Length  : "
        << header->len
        << " bytes"
        << endl;

    cout << "===================================" << endl;
}

int main()
{
    pcap_if_t* alldevs;
    pcap_if_t* d;

    char errbuf[PCAP_ERRBUF_SIZE];

    if(pcap_findalldevs(
        &alldevs,
        errbuf) == -1)
    {
        cout
            << "Error: "
            << errbuf
            << endl;

        return 1;
    }

    cout
        << "Available Interfaces:\n"
        << endl;

    int i = 0;

    for(d = alldevs;
        d;
        d = d->next)
    {
        cout
            << ++i
            << ". "
            << (d->description ?
                d->description :
                "No Description")
            << endl;
    }

    int choice;

    cout
        << "\nChoose interface: ";

    cin >> choice;

    d = alldevs;

    for(i = 1;
        i < choice;
        i++)
    {
        d = d->next;
    }

    pcap_t* handle =
        pcap_open_live(
            d->name,
            65536,
            1,
            1000,
            errbuf);

    if(handle == nullptr)
    {
        cout
            << "Unable to open adapter."
            << endl;

        return 1;
    }

    cout
        << "\nPacket Viewer Started...\n"
        << endl;

    cout
        << "Press Ctrl+C to stop.\n"
        << endl;

    pcap_loop(
        handle,
        0,
        packetHandler,
        nullptr);

    pcap_close(handle);

    pcap_freealldevs(alldevs);

    return 0;
}