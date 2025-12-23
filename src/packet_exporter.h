#pragma once

#include "packet_data.h"
#include <string>
#include <vector>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <ctime>

class PacketExporter {
public:
    // Export to CSV format
    static bool exportToCSV(const std::vector<PacketInfo>& packets, const std::string& filename) {
        std::ofstream file(filename);
        if (!file.is_open()) return false;
        
        // CSV Header
        file << "ID,Timestamp,Protocol,Source IP,Dest IP,Source Port,Dest Port,"
             << "Source MAC,Dest MAC,Length,Info\n";
        
        for (const auto& pkt : packets) {
            file << pkt.id << ","
                 << std::fixed << std::setprecision(6) << pkt.timestamp << ","
                 << escapeCSV(pkt.protocol) << ","
                 << escapeCSV(pkt.src_ip) << ","
                 << escapeCSV(pkt.dst_ip) << ","
                 << pkt.src_port << ","
                 << pkt.dst_port << ","
                 << escapeCSV(pkt.src_mac) << ","
                 << escapeCSV(pkt.dst_mac) << ","
                 << pkt.length << ","
                 << escapeCSV(pkt.info) << "\n";
        }
        
        file.close();
        return true;
    }
    
    // Export to JSON format
    static bool exportToJSON(const std::vector<PacketInfo>& packets, const std::string& filename) {
        std::ofstream file(filename);
        if (!file.is_open()) return false;
        
        file << "{\n";
        file << "  \"packets\": [\n";
        
        for (size_t i = 0; i < packets.size(); i++) {
            const auto& pkt = packets[i];
            
            file << "    {\n";
            file << "      \"id\": " << pkt.id << ",\n";
            file << "      \"timestamp\": " << std::fixed << std::setprecision(6) << pkt.timestamp << ",\n";
            file << "      \"protocol\": \"" << escapeJSON(pkt.protocol) << "\",\n";
            file << "      \"src_ip\": \"" << escapeJSON(pkt.src_ip) << "\",\n";
            file << "      \"dst_ip\": \"" << escapeJSON(pkt.dst_ip) << "\",\n";
            file << "      \"src_port\": " << pkt.src_port << ",\n";
            file << "      \"dst_port\": " << pkt.dst_port << ",\n";
            file << "      \"src_mac\": \"" << escapeJSON(pkt.src_mac) << "\",\n";
            file << "      \"dst_mac\": \"" << escapeJSON(pkt.dst_mac) << "\",\n";
            file << "      \"length\": " << pkt.length << ",\n";
            file << "      \"info\": \"" << escapeJSON(pkt.info) << "\"";
            
            // Add detailed layer info if available
            if (pkt.has_tcp) {
                file << ",\n      \"tcp\": {\n";
                file << "        \"src_port\": " << pkt.tcp.src_port << ",\n";
                file << "        \"dst_port\": " << pkt.tcp.dst_port << ",\n";
                file << "        \"seq_num\": " << pkt.tcp.seq_num << ",\n";
                file << "        \"ack_num\": " << pkt.tcp.ack_num << ",\n";
                file << "        \"flags\": \"" << pkt.tcp.flags_str << "\",\n";
                file << "        \"window\": " << pkt.tcp.window << "\n";
                file << "      }";
            }
            
            if (pkt.has_http) {
                file << ",\n      \"http\": {\n";
                if (pkt.http.is_request) {
                    file << "        \"type\": \"request\",\n";
                    file << "        \"method\": \"" << escapeJSON(pkt.http.method) << "\",\n";
                    file << "        \"uri\": \"" << escapeJSON(pkt.http.uri) << "\",\n";
                    file << "        \"host\": \"" << escapeJSON(pkt.http.host) << "\"\n";
                } else {
                    file << "        \"type\": \"response\",\n";
                    file << "        \"status_code\": " << pkt.http.status_code << ",\n";
                    file << "        \"status_text\": \"" << escapeJSON(pkt.http.status_text) << "\"\n";
                }
                file << "      }";
            }
            
            if (pkt.has_dns) {
                file << ",\n      \"dns\": {\n";
                file << "        \"is_query\": " << (pkt.dns.is_query ? "true" : "false") << ",\n";
                file << "        \"queries\": [";
                for (size_t j = 0; j < pkt.dns.queries.size(); j++) {
                    file << "\"" << escapeJSON(pkt.dns.queries[j]) << "\"";
                    if (j < pkt.dns.queries.size() - 1) file << ", ";
                }
                file << "],\n";
                file << "        \"responses\": [";
                for (size_t j = 0; j < pkt.dns.responses.size(); j++) {
                    file << "\"" << escapeJSON(pkt.dns.responses[j]) << "\"";
                    if (j < pkt.dns.responses.size() - 1) file << ", ";
                }
                file << "]\n";
                file << "      }";
            }
            
            file << "\n    }";
            if (i < packets.size() - 1) file << ",";
            file << "\n";
        }
        
        file << "  ],\n";
        file << "  \"total_packets\": " << packets.size() << ",\n";
        
        // Add timestamp
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        char buf[100];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&time));
        file << "  \"export_time\": \"" << buf << "\"\n";
        
        file << "}\n";
        file.close();
        return true;
    }
    
    // Export to plain text format
    static bool exportToText(const std::vector<PacketInfo>& packets, const std::string& filename) {
        std::ofstream file(filename);
        if (!file.is_open()) return false;
        
        file << "========================================\n";
        file << "Network Packet Capture Export\n";
        file << "Total Packets: " << packets.size() << "\n";
        
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        char buf[100];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&time));
        file << "Export Time: " << buf << "\n";
        file << "========================================\n\n";
        
        for (const auto& pkt : packets) {
            file << "Packet #" << pkt.id << "\n";
            file << "  Time: " << std::fixed << std::setprecision(6) << pkt.timestamp << "\n";
            file << "  Protocol: " << pkt.protocol << "\n";
            file << "  " << pkt.src_ip << ":" << pkt.src_port 
                 << " -> " << pkt.dst_ip << ":" << pkt.dst_port << "\n";
            file << "  Length: " << pkt.length << " bytes\n";
            file << "  Info: " << pkt.info << "\n";
            file << "  MAC: " << pkt.src_mac << " -> " << pkt.dst_mac << "\n";
            
            if (pkt.has_tcp) {
                file << "  TCP: Seq=" << pkt.tcp.seq_num 
                     << " Ack=" << pkt.tcp.ack_num
                     << " Flags=[" << pkt.tcp.flags_str << "]\n";
            }
            
            if (pkt.has_http) {
                if (pkt.http.is_request) {
                    file << "  HTTP Request: " << pkt.http.method << " " << pkt.http.uri << "\n";
                } else {
                    file << "  HTTP Response: " << pkt.http.status_code << " " << pkt.http.status_text << "\n";
                }
            }
            
            if (pkt.has_dns) {
                file << "  DNS: " << (pkt.dns.is_query ? "Query" : "Response");
                if (!pkt.dns.queries.empty()) {
                    file << " - " << pkt.dns.queries[0];
                }
                if (!pkt.dns.responses.empty()) {
                    file << " -> " << pkt.dns.responses[0];
                }
                file << "\n";
            }
            
            file << "\n";
        }
        
        file.close();
        return true;
    }
    
private:
    static std::string escapeCSV(const std::string& str) {
        if (str.find(',') != std::string::npos || 
            str.find('"') != std::string::npos || 
            str.find('\n') != std::string::npos) {
            std::string escaped = "\"";
            for (char c : str) {
                if (c == '"') escaped += "\"\"";
                else escaped += c;
            }
            escaped += "\"";
            return escaped;
        }
        return str;
    }
    
    static std::string escapeJSON(const std::string& str) {
        std::string escaped;
        for (char c : str) {
            switch (c) {
                case '"': escaped += "\\\""; break;
                case '\\': escaped += "\\\\"; break;
                case '\n': escaped += "\\n"; break;
                case '\r': escaped += "\\r"; break;
                case '\t': escaped += "\\t"; break;
                default: escaped += c; break;
            }
        }
        return escaped;
    }
};
