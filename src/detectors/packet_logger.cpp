#include <pcap.h>
#include <iostream>

using namespace std;

pcap_dumper_t* dumpFile = nullptr;

void packetHandler(
    u_char*,
    const struct pcap_pkthdr* header,
    const u_char* packet)
{
    static long long packetCount = 0;

    packetCount++;

    cout
        << "Captured Packet #"
        << packetCount
        << " | Length: "
        << header->len
        << " bytes"
        << endl;

    // Write packet to pcap file
    pcap_dump(
        (u_char*)dumpFile,
        header,
        packet);
}

int main()
{
    pcap_if_t* alldevs;
    pcap_if_t* d;

    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        cout
            << "Error finding adapters: "
            << errbuf
            << endl;

        return 1;
    }

    cout
        << "Available Interfaces:\n"
        << endl;

    int i = 0;

    for (d = alldevs; d; d = d->next)
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
        cout
            << "Unable to open adapter."
            << endl;

        pcap_freealldevs(alldevs);

        return 1;
    }

    dumpFile =
        pcap_dump_open(
            handle,
            "captures\\traffic_capture.pcap");

    if (dumpFile == nullptr)
    {
        cout
            << "Unable to create capture file."
            << endl;

        pcap_close(handle);
        pcap_freealldevs(alldevs);

        return 1;
    }

    cout
        << "\nPacket logging started..."
        << endl;

    cout
        << "\nSaving packets to:"
        << endl;

    cout
        << "captures\\traffic_capture.pcap"
        << endl;

    cout
        << "\nPress Ctrl+C to stop.\n"
        << endl;

    pcap_loop(
        handle,
        0,
        packetHandler,
        nullptr);

    pcap_dump_close(dumpFile);

    pcap_close(handle);

    pcap_freealldevs(alldevs);

    return 0;
}