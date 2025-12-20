#pragma once

#include <string>
#include <cstdint>
#include <vector>
#include <mutex>
#include <map>

// TCP Flags
struct TCPFlags {
    bool FIN = false;
    bool SYN = false;
    bool RST = false;
    bool PSH = false;
    bool ACK = false;
    bool URG = false;
    bool ECE = false;
    bool CWR = false;
};

// Ethernet Layer
struct EthernetInfo {
    std::string src_mac;
    std::string dst_mac;
    uint16_t ether_type = 0;
    std::string ether_type_name;
};

// IPv4 Layer
struct IPv4Info {
    uint8_t version = 0;
    uint8_t ihl = 0;
    uint8_t tos = 0;
    uint16_t total_length = 0;
    uint16_t identification = 0;
    bool df_flag = false;  // Don't Fragment
    bool mf_flag = false;  // More Fragments
    uint16_t fragment_offset = 0;
    uint8_t ttl = 0;
    uint8_t protocol = 0;
    std::string protocol_name;
    uint16_t checksum = 0;
    std::string src_ip;
    std::string dst_ip;
};

// TCP Layer
struct TCPInfo {
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint32_t seq_num = 0;
    uint32_t ack_num = 0;
    uint8_t data_offset = 0;
    TCPFlags flags;
    uint16_t window = 0;
    uint16_t checksum = 0;
    uint16_t urgent_ptr = 0;
    std::string flags_str;
};

// UDP Layer
struct UDPInfo {
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint16_t length = 0;
    uint16_t checksum = 0;
};

// HTTP Info
struct HTTPInfo {
    bool is_request = false;
    bool is_response = false;
    std::string method;      // GET, POST, etc
    std::string uri;
    std::string version;
    int status_code = 0;
    std::string status_text;
    std::string host;
    std::string user_agent;
    std::string content_type;
    int content_length = 0;
};

// DNS Info
struct DNSInfo {
    uint16_t transaction_id = 0;
    bool is_query = true;
    uint16_t questions = 0;
    uint16_t answers = 0;
    std::vector<std::string> queries;
    std::vector<std::string> responses;
};

// ICMP Info
struct ICMPInfo {
    uint8_t type = 0;
    uint8_t code = 0;
    std::string type_name;
    uint16_t checksum = 0;
    uint16_t identifier = 0;
    uint16_t sequence = 0;
};

// ARP Info
struct ARPInfo {
    uint16_t operation = 0;
    std::string operation_name;
    std::string sender_mac;
    std::string sender_ip;
    std::string target_mac;
    std::string target_ip;
};

struct PacketInfo {
    int id;
    double timestamp;
    std::string src_mac;
    std::string dst_mac;
    std::string src_ip;
    std::string dst_ip;
    std::string protocol;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t length;
    std::string info;
    std::vector<uint8_t> raw_data;
    
    // Detailed layer info
    EthernetInfo ethernet;
    IPv4Info ipv4;
    TCPInfo tcp;
    UDPInfo udp;
    HTTPInfo http;
    DNSInfo dns;
    ICMPInfo icmp;
    ARPInfo arp;
    
    bool has_ethernet = false;
    bool has_ipv4 = false;
    bool has_tcp = false;
    bool has_udp = false;
    bool has_http = false;
    bool has_dns = false;
    bool has_icmp = false;
    bool has_arp = false;
};

class PacketBuffer {
public:
    void addPacket(const PacketInfo& packet) {
        std::lock_guard<std::mutex> lock(mutex_);
        packets_.push_back(packet);
        if (packets_.size() > max_packets_) {
            packets_.erase(packets_.begin());
        }
    }
    
    std::vector<PacketInfo> getPackets() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return packets_;
    }
    
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        packets_.clear();
    }
    
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return packets_.size();
    }
    
    void setMaxPackets(size_t max) {
        std::lock_guard<std::mutex> lock(mutex_);
        max_packets_ = max;
    }

private:
    mutable std::mutex mutex_;
    std::vector<PacketInfo> packets_;
    size_t max_packets_ = 1000;
};
