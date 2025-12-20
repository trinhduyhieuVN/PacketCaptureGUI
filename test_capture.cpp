// Simple packet capture test - minimal code
#include <pcap.h>
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma pack(push, 1)
struct EthHeader {
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t type;
};
#pragma pack(pop)

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    static int count = 0;
    count++;
    
    const EthHeader* eth = (const EthHeader*)packet;
    uint16_t type = ntohs(eth->type);
    
    std::cout << "Packet #" << count 
              << " - Length: " << pkthdr->len 
              << " - EtherType: 0x" << std::hex << type << std::dec
              << std::endl;
    
    if (count >= 10) {
        std::cout << "\nReceived 10 packets successfully! Press Ctrl+C to stop." << std::endl;
    }
}

int main() {
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    std::cout << "=== Simple Packet Capture Test ===\n" << std::endl;
    
    // Find devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "ERROR finding devices: " << errbuf << std::endl;
        return 1;
    }
    
    // List devices
    std::cout << "Available interfaces:" << std::endl;
    int i = 0;
    for (pcap_if_t* d = alldevs; d != NULL; d = d->next) {
        std::cout << i << ". " << (d->description ? d->description : d->name) << std::endl;
        i++;
    }
    
    // Select device (default to first one with non-loopback flag)
    pcap_if_t* selected = alldevs;
    int selected_idx = 0;
    
    // Try to find WiFi or Ethernet adapter
    i = 0;
    for (pcap_if_t* d = alldevs; d != NULL; d = d->next) {
        if (d->description) {
            std::string desc = d->description;
            if (desc.find("Wi-Fi") != std::string::npos || 
                desc.find("Ethernet") != std::string::npos ||
                desc.find("Realtek") != std::string::npos ||
                desc.find("MediaTek") != std::string::npos) {
                selected = d;
                selected_idx = i;
                break;
            }
        }
        i++;
    }
    
    std::cout << "\nUsing device #" << selected_idx << ": " 
              << (selected->description ? selected->description : selected->name) << std::endl;
    std::cout << "Device name: " << selected->name << std::endl;
    
    // Open device
    pcap_t* handle = pcap_open_live(selected->name, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        std::cerr << "\nERROR opening device: " << errbuf << std::endl;
        std::cerr << "Make sure you run this as Administrator!" << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }
    
    std::cout << "\nCapture started! Waiting for packets..." << std::endl;
    std::cout << "Try opening a web browser or ping google.com to generate traffic.\n" << std::endl;
    
    // Capture packets
    pcap_loop(handle, 0, packet_handler, NULL);
    
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    
    return 0;
}
