#include <iostream>
#include <pcap.h>

int main() {
    pcap_if_t* alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error: " << errbuf << "\n";
        return 1;
    }

    int i = 0;

    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        std::cout << ++i << ". "
                  << (d->name ? d->name : "Unknown")
                  << "\n";

        if (d->description)
            std::cout << "   " << d->description << "\n";
    }

    pcap_freealldevs(alldevs);

    return 0;
}
