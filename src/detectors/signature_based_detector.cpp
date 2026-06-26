#include "signature_based_detector.h"
#include "packet_structures.h"
#include "logger.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>

using namespace std;

static vector<string> signatures;

void loadSignatures()
{
    signatures.clear();

    ifstream file("signatures.txt");

    if (!file.is_open())
    {
        cout << "[Signature Detector] signatures.txt not found." << endl;

        // Default signatures
        signatures.push_back("cmd.exe");
        signatures.push_back("/etc/passwd");
        signatures.push_back("UNION SELECT");
        signatures.push_back("DROP TABLE");
        signatures.push_back("<script>");
        signatures.push_back("xp_cmdshell");
        signatures.push_back("../");
        signatures.push_back("' OR '1'='1");

        return;
    }

    string line;

    while (getline(file, line))
    {
        if (line.empty())
            continue;

        if (line[0] == '#')
            continue;

        signatures.push_back(line);
    }

    cout << "[Signature Detector] Loaded "
         << signatures.size()
         << " signatures."
         << endl;
}

void detectSignatures(
    const u_char* packet,
    const pcap_pkthdr* header)
{
    if (signatures.empty())
        loadSignatures();

    const EthernetHeader* eth =
        (const EthernetHeader*)packet;

    if (ntohs(eth->type) != 0x0800)
        return;

    const IPHeader* ip =
        (const IPHeader*)(packet + sizeof(EthernetHeader));

    if (ip->protocol != IPPROTO_TCP)
        return;

    int ipHeaderLength =
        (ip->ver_ihl & 0x0F) * 4;

    const TCPHeader* tcp =
        (const TCPHeader*)
        ((const u_char*)ip + ipHeaderLength);

    int tcpHeaderLength =
        ((tcp->data_offset >> 4) & 0x0F) * 4;

    const char* payload =
        (const char*)tcp + tcpHeaderLength;

    int payloadLength =
        header->caplen -
        (
            sizeof(EthernetHeader) +
            ipHeaderLength +
            tcpHeaderLength
        );

    if (payloadLength <= 0)
        return;

    string data(payload, payloadLength);

    string srcIP =
        inet_ntoa(*(in_addr*)&ip->src_ip);

    string dstIP =
        inet_ntoa(*(in_addr*)&ip->dest_ip);

    for (const auto& sig : signatures)
    {
        if (data.find(sig) != string::npos)
        {
            cout << endl;
            cout << "======================================" << endl;
            cout << "[SIGNATURE DETECTED]" << endl;
            cout << "Signature : " << sig << endl;
            cout << "Source IP : " << srcIP << endl;
            cout << "Dest IP   : " << dstIP << endl;
            cout << "======================================" << endl;

            logAlert(
                "Signature detected: " +
                sig +
                " Source: " +
                srcIP +
                " Destination: " +
                dstIP);
        }
    }
}