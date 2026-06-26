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

void packetHandler(
    u_char*,
    const struct pcap_pkthdr* header,
    const u_char* packet)
{
    EthernetHeader* eth =
        (EthernetHeader*)packet;

    // Process only IPv4 packets
    if (ntohs(eth->type) != 0x0800)
        return;

    IPHeader* ip =
        (IPHeader*)(packet + sizeof(EthernetHeader));

    int ipHeaderLength =
        (ip->ver_ihl & 0x0F) * 4;

    char srcIp[INET_ADDRSTRLEN];
    char dstIp[INET_ADDRSTRLEN];

    in_addr src, dst;

    src.S_un.S_addr = ip->src_ip;
    dst.S_un.S_addr = ip->dest_ip;

    InetNtopA(AF_INET, &src, srcIp, INET_ADDRSTRLEN);
    InetNtopA(AF_INET, &dst, dstIp, INET_ADDRSTRLEN);

    // TCP Packets
    if (ip->protocol == 6)
    {
        TCPHeader* tcp =
            (TCPHeader*)
            (packet
            + sizeof(EthernetHeader)
            + ipHeaderLength);

        unsigned char flags = tcp->flags;

        bool syn = flags & 0x02;
        bool ack = flags & 0x10;
        bool fin = flags & 0x01;
        bool rst = flags & 0x04;

        cout
            << srcIp
            << ":"
            << ntohs(tcp->src_port)
            << " -> "
            << dstIp
            << ":"
            << ntohs(tcp->dst_port)
            << " | TCP ";

        if (syn) cout << "[SYN] ";
        if (ack) cout << "[ACK] ";
        if (fin) cout << "[FIN] ";
        if (rst) cout << "[RST] ";

        cout << endl;
    }

    // UDP Packets
    else if (ip->protocol == 17)
    {
        UDPHeader* udp =
            (UDPHeader*)
            (packet
            + sizeof(EthernetHeader)
            + ipHeaderLength);

        cout
            << srcIp
            << ":"
            << ntohs(udp->src_port)
            << " -> "
            << dstIp
            << ":"
            << ntohs(udp->dst_port)
            << " | UDP"
            << endl;
    }
}

int main()
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        cout << "Error: " << errbuf << endl;
        return 1;
    }

    int i = 0;

    cout << "Available Interfaces:\n" << endl;

    for (d = alldevs; d; d = d->next)
    {
        cout << ++i << ". "
             << (d->description ?
                 d->description :
                 "No Description")
             << endl;
    }

    int choice;

    cout << "\nChoose interface: ";
    cin >> choice;

    d = alldevs;

    for (i = 1; i < choice; i++)
        d = d->next;

    pcap_t* handle =
        pcap_open_live(
            d->name,
            65536,
            1,
            1000,
            errbuf);

    if (handle == nullptr)
    {
        cout << "Unable to open adapter." << endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    cout << "\nCapturing...\n" << endl;

    pcap_loop(
        handle,
        0,
        packetHandler,
        nullptr);

    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}