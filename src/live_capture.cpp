#include <iostream>
#include <pcap.h>

int main() {
    const char* device =
        "\\Device\\NPF_{7102FEC2-B45B-4978-860B-DC3F51B409C7}";

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(
        device,
        65536,
        1,
        1000,
        errbuf
    );

    if (handle == nullptr) {
        std::cerr << "Failed to open device: "
                  << errbuf << std::endl;
        return 1;
    }

    std::cout << "Live capture started!\n";
    std::cout << "Listening on Wi-Fi...\n";
    std::cout << "Press Ctrl+C to stop.\n\n";

    pcap_pkthdr* header;
    const u_char* packet;

    int packet_count = 0;

    while (true) {
        int result = pcap_next_ex(handle, &header, &packet);

        if (result == 1) {
            packet_count++;

            std::cout << "Packet "
                      << packet_count
                      << " | Length: "
                      << header->caplen
                      << " bytes"
                      << std::endl;
        }
        else if (result == 0) {
            continue;
        }
        else {
            std::cerr << "Capture error: "
                      << pcap_geterr(handle)
                      << std::endl;
            break;
        }
    }

    pcap_close(handle);

    return 0;
}