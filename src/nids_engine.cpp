#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <iostream>
#include <fstream>
#include <unordered_map>
#include <set>
#include <ctime>

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

struct ICMPHeader
{
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
};

#pragma pack(pop)

unordered_map<string,int> synCounter;
unordered_map<string,set<int>> portTracker;
unordered_map<string,int> icmpCounter;

long long totalPackets = 0;
long long tcpPackets = 0;
long long udpPackets = 0;
long long icmpPackets = 0;

ofstream logFile("alerts.log", ios::app);

void logAlert(const string& msg)
{
    time_t now = time(nullptr);

    char buffer[64];

    ctime_s(buffer,sizeof(buffer),&now);

    string timeStr(buffer);

    timeStr.pop_back();

    cout << "[ALERT] " << msg << endl;

    logFile
        << "["
        << timeStr
        << "] "
        << msg
        << endl;
}

string identifyProtocol(int port)
{
    switch(port)
    {
        case 80:
            return "HTTP";

        case 443:
            return "HTTPS";

        case 53:
            return "DNS";

        case 21:
            return "FTP";

        case 22:
            return "SSH";

        case 23:
            return "TELNET";

        case 25:
            return "SMTP";

        case 110:
            return "POP3";

        case 143:
            return "IMAP";

        case 8009:
            return "Google Cast";

        default:
            return "UNKNOWN";
    }
}

void packetHandler(
    u_char*,
    const pcap_pkthdr* header,
    const u_char* packet)
{
    totalPackets++;

    EthernetHeader* eth =
        (EthernetHeader*)packet;

    if(ntohs(eth->type) != 0x0800)
        return;

    IPHeader* ip =
        (IPHeader*)(packet + sizeof(EthernetHeader));

    int ipHeaderLength =
        (ip->ver_ihl & 0x0F) * 4;

    char srcIp[INET_ADDRSTRLEN];
    char dstIp[INET_ADDRSTRLEN];

    in_addr src,dst;

    src.S_un.S_addr = ip->src_ip;
    dst.S_un.S_addr = ip->dest_ip;

    InetNtopA(AF_INET,&src,srcIp,INET_ADDRSTRLEN);
    InetNtopA(AF_INET,&dst,dstIp,INET_ADDRSTRLEN);

    string sourceIP(srcIp);
    string destinationIP(dstIp);

    if(ip->protocol == 6)
    {
        tcpPackets++;

        TCPHeader* tcp =
            (TCPHeader*)
            (packet
            + sizeof(EthernetHeader)
            + ipHeaderLength);

        int srcPort =
            ntohs(tcp->src_port);

        int dstPort =
            ntohs(tcp->dst_port);

        string protocol =
            identifyProtocol(dstPort);

        cout
            << sourceIP
            << ":"
            << srcPort
            << " -> "
            << destinationIP
            << ":"
            << dstPort
            << " | "
            << protocol
            << endl;

        bool syn =
            (tcp->flags & 0x02);

        bool ack =
            (tcp->flags & 0x10);

        if(syn && !ack)
        {
            synCounter[sourceIP]++;

            if(synCounter[sourceIP] > 100)
            {
                logAlert(
                    "Possible SYN Flood from "
                    + sourceIP);
            }
        }

        portTracker[sourceIP]
            .insert(dstPort);

        if(portTracker[sourceIP]
            .size() > 30)
        {
            logAlert(
                "Possible Port Scan from "
                + sourceIP);
        }

        if(dstPort == 23)
        {
            logAlert(
                "TELNET traffic detected from "
                + sourceIP);
        }

        if(dstPort == 21)
        {
            logAlert(
                "FTP traffic detected from "
                + sourceIP);
        }
    }

    else if(ip->protocol == 17)
    {
        udpPackets++;

        UDPHeader* udp =
            (UDPHeader*)
            (packet
            + sizeof(EthernetHeader)
            + ipHeaderLength);

        int dstPort =
            ntohs(udp->dst_port);

        string protocol =
            identifyProtocol(dstPort);

        cout
            << sourceIP
            << " -> "
            << destinationIP
            << " | "
            << protocol
            << " (UDP)"
            << endl;

        if(dstPort == 53)
        {
            cout
                << "DNS Query Detected"
                << endl;
        }
    }

    else if(ip->protocol == 1)
    {
        icmpPackets++;

        icmpCounter[sourceIP]++;

        cout
            << sourceIP
            << " -> "
            << destinationIP
            << " | ICMP"
            << endl;

        if(icmpCounter[sourceIP] > 100)
        {
            logAlert(
                "Possible ICMP Flood from "
                + sourceIP);
        }
    }

    if(totalPackets % 100 == 0)
    {
        cout << endl;
        cout << "========= TRAFFIC STATS ========="
             << endl;

        cout << "Total Packets : "
             << totalPackets
             << endl;

        cout << "TCP Packets   : "
             << tcpPackets
             << endl;

        cout << "UDP Packets   : "
             << udpPackets
             << endl;

        cout << "ICMP Packets  : "
             << icmpPackets
             << endl;

        cout << "================================="
             << endl
             << endl;
    }
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

    for(d = alldevs; d; d = d->next)
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
        << "\n===== NIDS ENGINE STARTED =====\n"
        << endl;

    pcap_loop(
        handle,
        0,
        packetHandler,
        nullptr);

    pcap_close(handle);

    pcap_freealldevs(alldevs);

    logFile.close();

    return 0;
}