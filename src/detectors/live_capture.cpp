#include <pcap.h>
#include <iostream>

using namespace std;

void packetHandler(
    u_char* userData,
    const struct pcap_pkthdr* pkthdr,
    const u_char* packet)
{
    static int packetCount = 0;

    cout << "Packet #" << ++packetCount
         << " | Length: "
         << pkthdr->len
         << " bytes" << endl;
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

    cout << "Available Interfaces:\n";

    for (d = alldevs; d; d = d->next)
    {
        cout << ++i << ". "
             << (d->description ? d->description : "No Description")
             << endl;
    }

    int choice;

    cout << "\nChoose interface: ";
    cin >> choice;

    d = alldevs;

    for (i = 1; i < choice; i++)
        d = d->next;

    pcap_t* handle = pcap_open_live(
        d->name,
        65536,
        1,
        1000,
        errbuf);

    if (handle == nullptr)
    {
        cout << "Unable to open adapter." << endl;
        return 1;
    }

    cout << "\nCapturing packets...\n";
    cout << "Press Ctrl+C to stop.\n\n";

    pcap_loop(handle, 0, packetHandler, nullptr);

    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}