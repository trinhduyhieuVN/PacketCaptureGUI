#pragma once

#include "packet_data.h"
#include <pcap.h>
#include <thread>
#include <atomic>
#include <functional>

class PacketCapture {
public:
    using PacketCallback = std::function<void(const PacketInfo&)>;
    
    PacketCapture();
    ~PacketCapture();
    
    // Live capture
    bool start(const std::string& device, PacketCallback callback);
    void stop();
    bool isRunning() const { return running_; }
    
    // BPF Filtering
    bool setBPFFilter(const std::string& filter);
    std::string getLastError() const { return last_error_; }
    
    // Save/Load .pcap files
    bool startSavingPcap(const std::string& filename);
    void stopSavingPcap();
    bool isSavingPcap() const { return pcap_dumper_ != nullptr; }
    
    bool loadPcapFile(const std::string& filename, PacketCallback callback);
    
    static std::vector<std::pair<std::string, std::string>> getDevices();
    
private:
    void captureThread();
    static void packetHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);
    
    pcap_t* handle_;
    pcap_dumper_t* pcap_dumper_;
    std::thread capture_thread_;
    std::atomic<bool> running_;
    std::string device_;
    PacketCallback callback_;
    int packet_counter_;
    std::string last_error_;
};
