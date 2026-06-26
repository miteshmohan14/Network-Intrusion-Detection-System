#include "http_monitor.h"
#include "packet_structures.h"
#include "logger.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <iostream>
#include <string>
#include <algorithm>

using namespace std;

bool containsSuspiciousPattern(const string& payload)
{
    static const string patterns[] =
    {
        "../",
        "cmd.exe",
        "/etc/passwd",
        "UNION SELECT",
        "DROP TABLE",
        "<script>",
        "' OR '1'='1",
        "xp_cmdshell"
    };

    for (const auto& pattern : patterns)
    {
        if (payload.find(pattern) != string::npos)
            return true;
    }

    return false;
}

string extractHost(const string& payload)
{
    size_t pos = payload.find("Host:");

    if (pos == string::npos)
        return "Unknown";

    pos += 5;

    while (pos < payload.size() &&
           (payload[pos] == ' ' || payload[pos] == '\t'))
        pos++;

    size_t end = payload.find("\r\n", pos);

    if (end == string::npos)
        return "Unknown";

    return payload.substr(pos, end - pos);
}

void monitorHTTP(
    const u_char* packet,
    const pcap_pkthdr* header)
{
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

    unsigned short srcPort =
        ntohs(tcp->src_port);

    unsigned short dstPort =
        ntohs(tcp->dst_port);

    if (srcPort != 80 &&
        dstPort != 80 &&
        srcPort != 8080 &&
        dstPort != 8080)
        return;

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

    string httpData(payload, payloadLength);

    if (httpData.rfind("GET ", 0) != 0 &&
        httpData.rfind("POST ", 0) != 0 &&
        httpData.rfind("PUT ", 0) != 0 &&
        httpData.rfind("DELETE ", 0) != 0 &&
        httpData.rfind("HEAD ", 0) != 0)
    {
        return;
    }

    string srcIP =
        inet_ntoa(*(in_addr*)&ip->src_ip);

    string dstIP =
        inet_ntoa(*(in_addr*)&ip->dest_ip);

    string host =
        extractHost(httpData);

    string method;

    if (httpData.rfind("GET ", 0) == 0)
        method = "GET";
    else if (httpData.rfind("POST ", 0) == 0)
        method = "POST";
    else if (httpData.rfind("PUT ", 0) == 0)
        method = "PUT";
    else if (httpData.rfind("DELETE ", 0) == 0)
        method = "DELETE";
    else
        method = "HEAD";

    cout << "[HTTP] "
         << srcIP
         << " -> "
         << dstIP
         << endl;

    cout << "Method : "
         << method
         << endl;

    cout << "Host   : "
         << host
         << endl;

    logAlert(
        "HTTP " +
        method +
        " request to " +
        host);

    if (containsSuspiciousPattern(httpData))
    {
        cout << endl;
        cout << "=====================================" << endl;
        cout << "[ALERT] Suspicious HTTP Request" << endl;
        cout << "Source IP : " << srcIP << endl;
        cout << "Host      : " << host << endl;
        cout << "=====================================" << endl;

        logAlert(
            "Suspicious HTTP payload detected from " +
            srcIP +
            " to " +
            host);
    }
}