// nids_engine_v2.cpp

#include <pcap.h>
#include <iostream>

#include "packet_structures.h"
#include "logger.h"

#include "protocol_identifier.h"
#include "syn_flood_detector.h"
#include "port_scan_detector.h"
#include "arp_spoof_detector.h"
#include "dns_monitor.h"
#include "icmp_flood_detector.h"
#include "http_monitor.h"
#include "signature_based_detector.h"
#include "traffic_statistics.h"
#include "blacklist_detector.h"
#include "rule_engine.h"
#include "anomaly_detector.h"

using namespace std;

void processPacket(
    u_char*,
    const struct pcap_pkthdr* header,
    const u_char* packet)
{
    detectProtocol(packet, header);

    detectSynFlood(packet, header);

    detectPortScan(packet, header);

    detectArpSpoof(packet, header);

    monitorDNS(packet, header);

    detectICMPFlood(packet, header);

    monitorHTTP(packet, header);

    detectSignatures(packet, header);

    detectBlacklistIP(packet, header);

    detectRuleMatch(packet, header);

    detectAnomaly(packet, header);

    updateTrafficStats(packet, header);
}

int main()
{
    initializeLogger();

    loadBlacklist();

    loadRules();

    pcap_if_t* alldevs;
    pcap_if_t* d;

    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        cout << "Error: " << errbuf << endl;
        return 1;
    }

    cout << "Available Interfaces:\n" << endl;

    int i = 0;

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

    if (!handle)
{
    cout << "Unable to open adapter." << endl;
    pcap_freealldevs(alldevs);
    return 1;
}

    cout << "\n===== NIDS ENGINE V2 STARTED =====\n"
         << endl;

    pcap_loop(
        handle,
        0,
        processPacket,
        nullptr);

    pcap_close(handle);

    pcap_freealldevs(alldevs);

    return 0;
}