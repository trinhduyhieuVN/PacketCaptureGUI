#pragma once

#include "packet_data.h"
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <algorithm>

// TCP Stream identifier (4-tuple)
struct TCPStreamKey {
    std::string client_ip;
    uint16_t client_port;
    std::string server_ip;
    uint16_t server_port;
    
    bool operator<(const TCPStreamKey& other) const {
        if (client_ip != other.client_ip) return client_ip < other.client_ip;
        if (client_port != other.client_port) return client_port < other.client_port;
        if (server_ip != other.server_ip) return server_ip < other.server_ip;
        return server_port < other.server_port;
    }
    
    std::string toString() const {
        return client_ip + ":" + std::to_string(client_port) + 
               " <-> " + server_ip + ":" + std::to_string(server_port);
    }
};

// TCP Stream segment
struct TCPSegment {
    uint32_t seq_num;
    std::vector<uint8_t> data;
    double timestamp;
    bool from_client;  // true if client->server, false if server->client
    
    bool operator<(const TCPSegment& other) const {
        return seq_num < other.seq_num;
    }
};

// Complete TCP Stream data
struct TCPStream {
    TCPStreamKey key;
    std::vector<TCPSegment> segments;
    std::vector<uint8_t> client_to_server_data;
    std::vector<uint8_t> server_to_client_data;
    int packet_count = 0;
    double start_time = 0.0;
    double end_time = 0.0;
    bool is_active = true;
    
    // Reassemble data from segments
    void reassemble() {
        client_to_server_data.clear();
        server_to_client_data.clear();
        
        // Sort segments by sequence number
        std::sort(segments.begin(), segments.end());
        
        for (const auto& seg : segments) {
            if (seg.from_client) {
                client_to_server_data.insert(client_to_server_data.end(), 
                                            seg.data.begin(), seg.data.end());
            } else {
                server_to_client_data.insert(server_to_client_data.end(), 
                                            seg.data.begin(), seg.data.end());
            }
        }
    }
    
    // Get total data size
    size_t getTotalSize() const {
        return client_to_server_data.size() + server_to_client_data.size();
    }
    
    // Export to readable text format
    std::string toText() const {
        std::stringstream ss;
        
        ss << "========================================\n";
        ss << "TCP Stream: " << key.toString() << "\n";
        ss << "Packets: " << packet_count << "\n";
        ss << "Duration: " << std::fixed << std::setprecision(3) 
           << (end_time - start_time) << " seconds\n";
        ss << "Client->Server: " << client_to_server_data.size() << " bytes\n";
        ss << "Server->Client: " << server_to_client_data.size() << " bytes\n";
        ss << "========================================\n\n";
        
        // Client to Server data
        if (!client_to_server_data.empty()) {
            ss << "===== Client -> Server =====\n";
            ss << dataToString(client_to_server_data, true) << "\n\n";
        }
        
        // Server to Client data
        if (!server_to_client_data.empty()) {
            ss << "===== Server -> Client =====\n";
            ss << dataToString(server_to_client_data, true) << "\n\n";
        }
        
        return ss.str();
    }
    
private:
    static std::string dataToString(const std::vector<uint8_t>& data, bool show_ascii) {
        std::stringstream ss;
        
        // Try to interpret as ASCII first
        bool is_text = true;
        for (uint8_t byte : data) {
            if (byte < 32 && byte != '\n' && byte != '\r' && byte != '\t') {
                if (byte > 126) {
                    is_text = false;
                    break;
                }
            }
        }
        
        if (is_text && show_ascii) {
            // Show as ASCII text
            for (uint8_t byte : data) {
                if (byte >= 32 && byte <= 126) {
                    ss << (char)byte;
                } else if (byte == '\n') {
                    ss << '\n';
                } else if (byte == '\r') {
                    // Skip
                } else if (byte == '\t') {
                    ss << '\t';
                } else {
                    ss << '.';
                }
            }
        } else {
            // Show as hex dump with ASCII
            size_t offset = 0;
            while (offset < data.size()) {
                // Offset
                ss << std::setw(4) << std::setfill('0') << std::hex << offset << "  ";
                
                // Hex bytes
                for (size_t i = 0; i < 16; i++) {
                    if (offset + i < data.size()) {
                        ss << std::setw(2) << std::setfill('0') << std::hex 
                           << (int)data[offset + i] << " ";
                    } else {
                        ss << "   ";
                    }
                    if (i == 7) ss << " ";
                }
                
                ss << " ";
                
                // ASCII representation
                for (size_t i = 0; i < 16 && offset + i < data.size(); i++) {
                    uint8_t byte = data[offset + i];
                    if (byte >= 32 && byte <= 126) {
                        ss << (char)byte;
                    } else {
                        ss << '.';
                    }
                }
                
                ss << "\n";
                offset += 16;
            }
        }
        
        return ss.str();
    }
};

// TCP Stream Tracker
class TCPStreamTracker {
public:
    // Add a packet to tracking
    void addPacket(const PacketInfo& packet) {
        if (!packet.has_tcp || !packet.has_ipv4) return;
        
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Create stream key (normalize so client is the one who initiated SYN)
        TCPStreamKey key;
        bool from_client;
        
        // Simple heuristic: lower port is usually client (or use SYN flag if available)
        if (packet.tcp.src_port < packet.tcp.dst_port || packet.tcp.flags.SYN) {
            key.client_ip = packet.src_ip;
            key.client_port = packet.tcp.src_port;
            key.server_ip = packet.dst_ip;
            key.server_port = packet.tcp.dst_port;
            from_client = true;
        } else {
            key.client_ip = packet.dst_ip;
            key.client_port = packet.tcp.dst_port;
            key.server_ip = packet.src_ip;
            key.server_port = packet.tcp.src_port;
            from_client = false;
        }
        
        // Get or create stream
        TCPStream& stream = streams_[key];
        if (stream.packet_count == 0) {
            stream.key = key;
            stream.start_time = packet.timestamp;
        }
        
        stream.packet_count++;
        stream.end_time = packet.timestamp;
        
        // Extract payload data (we saved raw_data in PacketInfo, but need to parse it)
        // For now, we'll track the packet but won't extract payload
        // In a full implementation, we'd extract TCP payload here
        
        // Mark stream as closed if FIN or RST
        if (packet.tcp.flags.FIN || packet.tcp.flags.RST) {
            stream.is_active = false;
        }
    }
    
    // Get all streams
    std::vector<TCPStream> getAllStreams() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<TCPStream> result;
        for (const auto& pair : streams_) {
            result.push_back(pair.second);
        }
        return result;
    }
    
    // Find stream containing a specific packet
    TCPStream* findStream(const PacketInfo& packet) {
        if (!packet.has_tcp || !packet.has_ipv4) return nullptr;
        
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Try both directions
        TCPStreamKey key1;
        key1.client_ip = packet.src_ip;
        key1.client_port = packet.tcp.src_port;
        key1.server_ip = packet.dst_ip;
        key1.server_port = packet.tcp.dst_port;
        
        TCPStreamKey key2;
        key2.client_ip = packet.dst_ip;
        key2.client_port = packet.tcp.dst_port;
        key2.server_ip = packet.src_ip;
        key2.server_port = packet.tcp.src_port;
        
        auto it1 = streams_.find(key1);
        if (it1 != streams_.end()) {
            return &it1->second;
        }
        
        auto it2 = streams_.find(key2);
        if (it2 != streams_.end()) {
            return &it2->second;
        }
        
        return nullptr;
    }
    
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        streams_.clear();
    }
    
    size_t getStreamCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return streams_.size();
    }
    
private:
    mutable std::mutex mutex_;
    std::map<TCPStreamKey, TCPStream> streams_;
};
