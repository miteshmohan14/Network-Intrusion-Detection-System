#include <pcap.h>
#include <iostream>
#include <winsock2.h>
#include <windows.h>
#include <tchar.h>

bool LoadNpcapDlls()
{
    TCHAR npcap_dir[512];

    UINT len = GetSystemDirectory(npcap_dir, 480);

    if (!len)
        return false;

    _tcscat_s(npcap_dir, 512, TEXT("\\Npcap"));

    if (SetDllDirectory(npcap_dir) == 0)
        return false;

    return true;
}

int main()
{
    WSADATA wsadata;

    if (WSAStartup(MAKEWORD(2,2), &wsadata) != 0)
    {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }

    if (!LoadNpcapDlls())
    {
        std::cerr << "Couldn't load Npcap DLLs\n";
        return 1;
    }

    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    int result = pcap_findalldevs(&alldevs, errbuf);

    std::cout << "pcap_findalldevs returned: "
              << result << std::endl;

    if (result == -1)
    {
        std::cerr << errbuf << std::endl;
        return 1;
    }

    int count = 0;

    for (pcap_if_t* d = alldevs; d; d = d->next)
    {
        count++;

        std::cout << count << ". ";

        if (d->name)
            std::cout << d->name;

        if (d->description)
            std::cout << " | " << d->description;

        std::cout << std::endl;
    }

    std::cout << "\nTotal Interfaces: "
              << count << std::endl;

    pcap_freealldevs(alldevs);

    WSACleanup();

    return 0;
}