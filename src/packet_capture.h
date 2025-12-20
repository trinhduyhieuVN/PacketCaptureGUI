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
    
    bool start(const std::string& device, PacketCallback callback);
    void stop();
    bool isRunning() const { return running_; }
    
    static std::vector<std::pair<std::string, std::string>> getDevices();
    
private:
    void captureThread();
    static void packetHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);
    
    pcap_t* handle_;
    std::thread capture_thread_;
    std::atomic<bool> running_;
    std::string device_;
    PacketCallback callback_;
    int packet_counter_;
};
