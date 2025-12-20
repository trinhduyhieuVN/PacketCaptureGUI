// Quick test to check if pcap can find devices
#include <pcap.h>
#include <iostream>

int main() {
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    std::cout << "Testing pcap_findalldevs()...\n" << std::endl;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "ERROR: pcap_findalldevs failed: " << errbuf << std::endl;
        return 1;
    }
    
    if (alldevs == NULL) {
        std::cout << "No devices found!" << std::endl;
        return 1;
    }
    
    int i = 0;
    for (pcap_if_t* d = alldevs; d != NULL; d = d->next) {
        i++;
        std::cout << "Device #" << i << ":" << std::endl;
        std::cout << "  Name: " << d->name << std::endl;
        std::cout << "  Desc: " << (d->description ? d->description : "No description") << std::endl;
        std::cout << "  Flags: " << d->flags << std::endl;
        std::cout << std::endl;
    }
    
    std::cout << "Total devices found: " << i << std::endl;
    
    pcap_freealldevs(alldevs);
    return 0;
}
