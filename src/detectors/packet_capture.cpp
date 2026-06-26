#include <pcap.h>
#include <iostream>

using namespace std;

int main()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        cout << "Error: " << errbuf << endl;
        return 1;
    }

    int i = 0;

    cout << "Available Interfaces:\n\n";

    for (d = alldevs; d; d = d->next)
    {
        cout << ++i << ". ";

        if (d->description)
            cout << d->description;
        else
            cout << "No Description";

        cout << endl;
    }

    pcap_freealldevs(alldevs);

    return 0;
}