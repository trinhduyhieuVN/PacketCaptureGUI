/*
 * Packet Capture Engine with Full Protocol Parsing
 * Supports: Ethernet, IPv4, TCP, UDP, ICMP, ARP, HTTP, DNS
 */

#include "packet_capture.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "ws2_32.lib")

// ============== Protocol Headers ==============

#pragma pack(push, 1)

struct EthHeader {
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t type;
};

struct IPv4Header {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
};

struct UDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

struct ICMPHeader {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
};

struct ARPHeader {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_len;
    uint8_t proto_len;
    uint16_t operation;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};

struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t questions;
    uint16_t answers;
    uint16_t authority;
    uint16_t additional;
};

#pragma pack(pop)

// ============== Helper Functions ==============

static std::string macToString(const uint8_t* mac) {
    char buf[18];
    sprintf_s(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

static std::string ipToString(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return buf;
}

static std::string ipBytesToString(const uint8_t* ip) {
    char buf[16];
    sprintf_s(buf, sizeof(buf), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    return buf;
}

static std::string getEtherTypeName(uint16_t type) {
    switch (type) {
        case 0x0800: return "IPv4";
        case 0x0806: return "ARP";
        case 0x86DD: return "IPv6";
        case 0x8100: return "VLAN";
        case 0x88CC: return "LLDP";
        default: return "Unknown (0x" + std::to_string(type) + ")";
    }
}

static std::string getIPProtocolName(uint8_t proto) {
    switch (proto) {
        case 1: return "ICMP";
        case 6: return "TCP";
        case 17: return "UDP";
        case 47: return "GRE";
        case 50: return "ESP";
        case 51: return "AH";
        case 89: return "OSPF";
        default: return "Unknown (" + std::to_string(proto) + ")";
    }
}

static std::string getICMPTypeName(uint8_t type) {
    switch (type) {
        case 0: return "Echo Reply";
        case 3: return "Destination Unreachable";
        case 4: return "Source Quench";
        case 5: return "Redirect";
        case 8: return "Echo Request";
        case 11: return "Time Exceeded";
        case 12: return "Parameter Problem";
        case 13: return "Timestamp Request";
        case 14: return "Timestamp Reply";
        default: return "Type " + std::to_string(type);
    }
}

static std::string getTCPFlagsString(uint8_t flags) {
    std::string result;
    if (flags & 0x01) result += "FIN ";
    if (flags & 0x02) result += "SYN ";
    if (flags & 0x04) result += "RST ";
    if (flags & 0x08) result += "PSH ";
    if (flags & 0x10) result += "ACK ";
    if (flags & 0x20) result += "URG ";
    if (flags & 0x40) result += "ECE ";
    if (flags & 0x80) result += "CWR ";
    if (result.empty()) result = "None";
    return result;
}

static std::string getServiceName(uint16_t port) {
    switch (port) {
        case 20: return "FTP-Data";
        case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "Telnet";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 67: return "DHCP-Server";
        case 68: return "DHCP-Client";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 143: return "IMAP";
        case 443: return "HTTPS";
        case 445: return "SMB";
        case 993: return "IMAPS";
        case 995: return "POP3S";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5432: return "PostgreSQL";
        case 8080: return "HTTP-Alt";
        default: return "";
    }
}

// ============== DNS Parsing ==============

static std::string parseDNSName(const uint8_t* data, int offset, int maxLen, const uint8_t* dnsStart) {
    std::string name;
    int pos = offset;
    int jumps = 0;
    
    while (pos < maxLen && jumps < 10) {
        uint8_t len = data[pos];
        
        if (len == 0) break;
        
        // Compression pointer
        if ((len & 0xC0) == 0xC0) {
            int pointer = ((len & 0x3F) << 8) | data[pos + 1];
            if (dnsStart && pointer < maxLen) {
                name += parseDNSName(dnsStart, pointer, maxLen, dnsStart);
            }
            break;
        }
        
        if (!name.empty()) name += ".";
        
        pos++;
        for (int i = 0; i < len && pos < maxLen; i++, pos++) {
            name += (char)data[pos];
        }
        jumps++;
    }
    
    return name;
}

static void parseDNS(PacketInfo& info, const uint8_t* data, int len) {
    if (len < (int)sizeof(DNSHeader)) return;
    
    const DNSHeader* dns = (const DNSHeader*)data;
    
    info.has_dns = true;
    info.dns.transaction_id = ntohs(dns->id);
    info.dns.is_query = !(ntohs(dns->flags) & 0x8000);
    info.dns.questions = ntohs(dns->questions);
    info.dns.answers = ntohs(dns->answers);
    
    // Parse queries
    int offset = sizeof(DNSHeader);
    for (int i = 0; i < info.dns.questions && offset < len; i++) {
        std::string qname = parseDNSName(data, offset, len, data);
        
        // Skip name
        while (offset < len && data[offset] != 0) {
            if ((data[offset] & 0xC0) == 0xC0) {
                offset += 2;
                break;
            }
            offset += data[offset] + 1;
        }
        if (offset < len && data[offset] == 0) offset++;
        
        // Skip QTYPE and QCLASS
        offset += 4;
        
        if (!qname.empty()) {
            info.dns.queries.push_back(qname);
        }
    }
    
    // Parse answers (simplified)
    for (int i = 0; i < info.dns.answers && offset < len - 12; i++) {
        // Skip name (may be compressed)
        if ((data[offset] & 0xC0) == 0xC0) {
            offset += 2;
        } else {
            while (offset < len && data[offset] != 0) {
                offset += data[offset] + 1;
            }
            offset++;
        }
        
        if (offset + 10 > len) break;
        
        uint16_t rtype = (data[offset] << 8) | data[offset + 1];
        uint16_t rdlen = (data[offset + 8] << 8) | data[offset + 9];
        offset += 10;
        
        if (rtype == 1 && rdlen == 4 && offset + 4 <= len) {  // A record
            std::string ip = ipBytesToString(data + offset);
            info.dns.responses.push_back(ip);
        }
        
        offset += rdlen;
    }
}

// ============== HTTP Parsing ==============

static void parseHTTP(PacketInfo& info, const uint8_t* data, int len) {
    if (len < 10) return;
    
    std::string payload((char*)data, std::min(len, 2048));
    
    // Check for HTTP request
    if (payload.substr(0, 4) == "GET " || payload.substr(0, 5) == "POST " ||
        payload.substr(0, 4) == "PUT " || payload.substr(0, 7) == "DELETE " ||
        payload.substr(0, 5) == "HEAD " || payload.substr(0, 8) == "OPTIONS ") {
        
        info.has_http = true;
        info.http.is_request = true;
        
        // Parse method
        size_t space1 = payload.find(' ');
        if (space1 != std::string::npos) {
            info.http.method = payload.substr(0, space1);
            
            size_t space2 = payload.find(' ', space1 + 1);
            if (space2 != std::string::npos) {
                info.http.uri = payload.substr(space1 + 1, space2 - space1 - 1);
                
                size_t newline = payload.find("\r\n", space2);
                if (newline != std::string::npos) {
                    info.http.version = payload.substr(space2 + 1, newline - space2 - 1);
                }
            }
        }
        
        // Parse Host header
        size_t hostPos = payload.find("Host: ");
        if (hostPos != std::string::npos) {
            size_t hostEnd = payload.find("\r\n", hostPos);
            if (hostEnd != std::string::npos) {
                info.http.host = payload.substr(hostPos + 6, hostEnd - hostPos - 6);
            }
        }
        
        // Parse User-Agent
        size_t uaPos = payload.find("User-Agent: ");
        if (uaPos != std::string::npos) {
            size_t uaEnd = payload.find("\r\n", uaPos);
            if (uaEnd != std::string::npos) {
                info.http.user_agent = payload.substr(uaPos + 12, std::min((size_t)50, uaEnd - uaPos - 12));
            }
        }
    }
    // Check for HTTP response
    else if (payload.substr(0, 5) == "HTTP/") {
        info.has_http = true;
        info.http.is_response = true;
        
        size_t space1 = payload.find(' ');
        if (space1 != std::string::npos) {
            info.http.version = payload.substr(0, space1);
            
            size_t space2 = payload.find(' ', space1 + 1);
            if (space2 != std::string::npos) {
                info.http.status_code = std::stoi(payload.substr(space1 + 1, space2 - space1 - 1));
                
                size_t newline = payload.find("\r\n", space2);
                if (newline != std::string::npos) {
                    info.http.status_text = payload.substr(space2 + 1, newline - space2 - 1);
                }
            }
        }
        
        // Parse Content-Type
        size_t ctPos = payload.find("Content-Type: ");
        if (ctPos != std::string::npos) {
            size_t ctEnd = payload.find("\r\n", ctPos);
            if (ctEnd != std::string::npos) {
                info.http.content_type = payload.substr(ctPos + 14, ctEnd - ctPos - 14);
            }
        }
    }
}

// ============== PacketCapture Implementation ==============

PacketCapture::PacketCapture() 
    : handle_(nullptr), pcap_dumper_(nullptr), running_(false), packet_counter_(0) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
}

PacketCapture::~PacketCapture() {
    stop();
    WSACleanup();
}

std::vector<std::pair<std::string, std::string>> PacketCapture::getDevices() {
    std::vector<std::pair<std::string, std::string>> devices;
    
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return devices;
    }
    
    for (pcap_if_t* d = alldevs; d != NULL; d = d->next) {
        std::string name = d->name;
        std::string desc = d->description ? d->description : "No description";
        devices.push_back({name, desc});
    }
    
    pcap_freealldevs(alldevs);
    return devices;
}

bool PacketCapture::start(const std::string& device, PacketCallback callback) {
    if (running_) return false;
    
    device_ = device;
    callback_ = callback;
    packet_counter_ = 0;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    handle_ = pcap_open_live(device.c_str(), 65536, 1, 1000, errbuf);
    
    if (handle_ == NULL) return false;
    
    running_ = true;
    capture_thread_ = std::thread(&PacketCapture::captureThread, this);
    
    return true;
}

void PacketCapture::stop() {
    if (!running_) return;
    
    running_ = false;
    
    if (handle_) pcap_breakloop(handle_);
    if (capture_thread_.joinable()) capture_thread_.join();
    
    // Stop saving pcap if active
    if (pcap_dumper_) {
        pcap_dump_close(pcap_dumper_);
        pcap_dumper_ = nullptr;
    }
    
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

void PacketCapture::captureThread() {
    pcap_loop(handle_, 0, packetHandler, (u_char*)this);
}

void PacketCapture::packetHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    PacketCapture* capture = (PacketCapture*)user;
    if (!capture->running_) return;
    
    PacketInfo info;
    info.id = ++capture->packet_counter_;
    info.timestamp = header->ts.tv_sec + header->ts.tv_usec / 1000000.0;
    info.length = header->len;
    info.src_port = 0;
    info.dst_port = 0;
    
    // ===== Parse Ethernet =====
    if (header->len < sizeof(EthHeader)) return;
    
    const EthHeader* eth = (const EthHeader*)packet;
    
    info.has_ethernet = true;
    info.ethernet.src_mac = macToString(eth->src);
    info.ethernet.dst_mac = macToString(eth->dest);
    info.ethernet.ether_type = ntohs(eth->type);
    info.ethernet.ether_type_name = getEtherTypeName(info.ethernet.ether_type);
    
    info.src_mac = info.ethernet.src_mac;
    info.dst_mac = info.ethernet.dst_mac;
    
    uint16_t ethertype = info.ethernet.ether_type;
    const u_char* payload = packet + sizeof(EthHeader);
    int payload_len = header->len - sizeof(EthHeader);
    
    // ===== Parse ARP =====
    if (ethertype == 0x0806 && payload_len >= (int)sizeof(ARPHeader)) {
        const ARPHeader* arp = (const ARPHeader*)payload;
        
        info.has_arp = true;
        info.protocol = "ARP";
        info.arp.operation = ntohs(arp->operation);
        info.arp.operation_name = (info.arp.operation == 1) ? "Request" : 
                                  (info.arp.operation == 2) ? "Reply" : "Unknown";
        info.arp.sender_mac = macToString(arp->sender_mac);
        info.arp.sender_ip = ipBytesToString(arp->sender_ip);
        info.arp.target_mac = macToString(arp->target_mac);
        info.arp.target_ip = ipBytesToString(arp->target_ip);
        
        info.src_ip = info.arp.sender_ip;
        info.dst_ip = info.arp.target_ip;
        
        std::stringstream ss;
        if (info.arp.operation == 1) {
            ss << "Who has " << info.arp.target_ip << "? Tell " << info.arp.sender_ip;
        } else {
            ss << info.arp.sender_ip << " is at " << info.arp.sender_mac;
        }
        info.info = ss.str();
    }
    // ===== Parse IPv4 =====
    else if (ethertype == 0x0800 && payload_len >= (int)sizeof(IPv4Header)) {
        const IPv4Header* ip = (const IPv4Header*)payload;
        
        info.has_ipv4 = true;
        info.ipv4.version = (ip->version_ihl >> 4) & 0x0F;
        info.ipv4.ihl = (ip->version_ihl & 0x0F) * 4;
        info.ipv4.tos = ip->tos;
        info.ipv4.total_length = ntohs(ip->total_length);
        info.ipv4.identification = ntohs(ip->id);
        
        uint16_t flags_offset = ntohs(ip->flags_offset);
        info.ipv4.df_flag = (flags_offset & 0x4000) != 0;
        info.ipv4.mf_flag = (flags_offset & 0x2000) != 0;
        info.ipv4.fragment_offset = flags_offset & 0x1FFF;
        
        info.ipv4.ttl = ip->ttl;
        info.ipv4.protocol = ip->protocol;
        info.ipv4.protocol_name = getIPProtocolName(ip->protocol);
        info.ipv4.checksum = ntohs(ip->checksum);
        info.ipv4.src_ip = ipToString(ip->src_ip);
        info.ipv4.dst_ip = ipToString(ip->dst_ip);
        
        info.src_ip = info.ipv4.src_ip;
        info.dst_ip = info.ipv4.dst_ip;
        
        int ip_hdr_len = info.ipv4.ihl;
        const u_char* transport = payload + ip_hdr_len;
        int transport_len = payload_len - ip_hdr_len;
        
        // ===== Parse ICMP =====
        if (ip->protocol == 1 && transport_len >= (int)sizeof(ICMPHeader)) {
            const ICMPHeader* icmp = (const ICMPHeader*)transport;
            
            info.has_icmp = true;
            info.protocol = "ICMP";
            info.icmp.type = icmp->type;
            info.icmp.code = icmp->code;
            info.icmp.type_name = getICMPTypeName(icmp->type);
            info.icmp.checksum = ntohs(icmp->checksum);
            info.icmp.identifier = ntohs(icmp->id);
            info.icmp.sequence = ntohs(icmp->seq);
            
            std::stringstream ss;
            ss << info.icmp.type_name;
            if (icmp->type == 0 || icmp->type == 8) {
                ss << " id=" << info.icmp.identifier << " seq=" << info.icmp.sequence;
            }
            info.info = ss.str();
        }
        // ===== Parse TCP =====
        else if (ip->protocol == 6 && transport_len >= (int)sizeof(TCPHeader)) {
            const TCPHeader* tcp = (const TCPHeader*)transport;
            
            info.has_tcp = true;
            info.protocol = "TCP";
            info.tcp.src_port = ntohs(tcp->src_port);
            info.tcp.dst_port = ntohs(tcp->dst_port);
            info.tcp.seq_num = ntohl(tcp->seq);
            info.tcp.ack_num = ntohl(tcp->ack);
            info.tcp.data_offset = ((tcp->data_offset >> 4) & 0x0F) * 4;
            info.tcp.window = ntohs(tcp->window);
            info.tcp.checksum = ntohs(tcp->checksum);
            info.tcp.urgent_ptr = ntohs(tcp->urgent);
            
            // Parse flags
            info.tcp.flags.FIN = (tcp->flags & 0x01) != 0;
            info.tcp.flags.SYN = (tcp->flags & 0x02) != 0;
            info.tcp.flags.RST = (tcp->flags & 0x04) != 0;
            info.tcp.flags.PSH = (tcp->flags & 0x08) != 0;
            info.tcp.flags.ACK = (tcp->flags & 0x10) != 0;
            info.tcp.flags.URG = (tcp->flags & 0x20) != 0;
            info.tcp.flags.ECE = (tcp->flags & 0x40) != 0;
            info.tcp.flags.CWR = (tcp->flags & 0x80) != 0;
            info.tcp.flags_str = getTCPFlagsString(tcp->flags);
            
            info.src_port = info.tcp.src_port;
            info.dst_port = info.tcp.dst_port;
            
            // Build info string
            std::stringstream ss;
            ss << info.tcp.src_port << " -> " << info.tcp.dst_port;
            ss << " [" << info.tcp.flags_str << "]";
            ss << " Seq=" << info.tcp.seq_num;
            if (info.tcp.flags.ACK) ss << " Ack=" << info.tcp.ack_num;
            ss << " Win=" << info.tcp.window;
            
            // Add service name
            std::string svc = getServiceName(info.tcp.src_port);
            if (svc.empty()) svc = getServiceName(info.tcp.dst_port);
            if (!svc.empty()) ss << " (" << svc << ")";
            
            info.info = ss.str();
            
            // Parse HTTP in TCP payload
            int tcp_hdr_len = info.tcp.data_offset;
            if (transport_len > tcp_hdr_len) {
                const u_char* app_data = transport + tcp_hdr_len;
                int app_len = transport_len - tcp_hdr_len;
                
                if (info.tcp.src_port == 80 || info.tcp.dst_port == 80 ||
                    info.tcp.src_port == 8080 || info.tcp.dst_port == 8080) {
                    parseHTTP(info, app_data, app_len);
                    
                    if (info.has_http) {
                        info.protocol = "HTTP";
                        if (info.http.is_request) {
                            info.info = info.http.method + " " + info.http.uri;
                            if (!info.http.host.empty()) {
                                info.info += " (Host: " + info.http.host + ")";
                            }
                        } else if (info.http.is_response) {
                            info.info = info.http.version + " " + 
                                       std::to_string(info.http.status_code) + " " + 
                                       info.http.status_text;
                        }
                    }
                }
            }
        }
        // ===== Parse UDP =====
        else if (ip->protocol == 17 && transport_len >= (int)sizeof(UDPHeader)) {
            const UDPHeader* udp = (const UDPHeader*)transport;
            
            info.has_udp = true;
            info.protocol = "UDP";
            info.udp.src_port = ntohs(udp->src_port);
            info.udp.dst_port = ntohs(udp->dst_port);
            info.udp.length = ntohs(udp->length);
            info.udp.checksum = ntohs(udp->checksum);
            
            info.src_port = info.udp.src_port;
            info.dst_port = info.udp.dst_port;
            
            std::stringstream ss;
            ss << info.udp.src_port << " -> " << info.udp.dst_port;
            ss << " Len=" << info.udp.length;
            
            // Parse DNS
            if (info.udp.src_port == 53 || info.udp.dst_port == 53) {
                const u_char* dns_data = transport + sizeof(UDPHeader);
                int dns_len = transport_len - sizeof(UDPHeader);
                
                parseDNS(info, dns_data, dns_len);
                
                if (info.has_dns) {
                    info.protocol = "DNS";
                    ss.str("");
                    
                    if (info.dns.is_query) {
                        ss << "Standard query";
                        if (!info.dns.queries.empty()) {
                            ss << " " << info.dns.queries[0];
                        }
                    } else {
                        ss << "Standard response";
                        if (!info.dns.queries.empty()) {
                            ss << " " << info.dns.queries[0];
                        }
                        if (!info.dns.responses.empty()) {
                            ss << " -> " << info.dns.responses[0];
                        }
                    }
                    info.info = ss.str();
                }
            } else {
                // Add service name
                std::string svc = getServiceName(info.udp.src_port);
                if (svc.empty()) svc = getServiceName(info.udp.dst_port);
                if (!svc.empty()) ss << " (" << svc << ")";
                
                info.info = ss.str();
            }
        }
        else {
            info.protocol = info.ipv4.protocol_name;
            info.info = "Protocol: " + info.ipv4.protocol_name;
        }
    }
    else {
        info.protocol = info.ethernet.ether_type_name;
        info.info = "EtherType: 0x" + std::to_string(ethertype);
    }
    
    // Copy raw data (limit to 512 bytes for display)
    size_t copy_len = std::min((size_t)header->len, (size_t)512);
    info.raw_data.assign(packet, packet + copy_len);
    
    // Save to pcap file if dumper is active
    if (capture->pcap_dumper_) {
        pcap_dump((u_char*)capture->pcap_dumper_, header, packet);
    }
    
    if (capture->callback_) {
        capture->callback_(info);
    }
}

// ============== BPF Filter ==============

bool PacketCapture::setBPFFilter(const std::string& filter) {
    if (!handle_) {
        last_error_ = "No active capture session";
        return false;
    }
    
    struct bpf_program fp;
    if (pcap_compile(handle_, &fp, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
        last_error_ = "Failed to compile filter: " + std::string(pcap_geterr(handle_));
        return false;
    }
    
    if (pcap_setfilter(handle_, &fp) == -1) {
        last_error_ = "Failed to set filter: " + std::string(pcap_geterr(handle_));
        pcap_freecode(&fp);
        return false;
    }
    
    pcap_freecode(&fp);
    last_error_.clear();
    return true;
}

// ============== Save/Load PCAP Files ==============

bool PacketCapture::startSavingPcap(const std::string& filename) {
    if (!handle_) {
        last_error_ = "No active capture session";
        return false;
    }
    
    if (pcap_dumper_) {
        last_error_ = "Already saving to a file";
        return false;
    }
    
    pcap_dumper_ = pcap_dump_open(handle_, filename.c_str());
    if (!pcap_dumper_) {
        last_error_ = "Failed to open dump file: " + std::string(pcap_geterr(handle_));
        return false;
    }
    
    last_error_.clear();
    return true;
}

void PacketCapture::stopSavingPcap() {
    if (pcap_dumper_) {
        pcap_dump_close(pcap_dumper_);
        pcap_dumper_ = nullptr;
    }
}

bool PacketCapture::loadPcapFile(const std::string& filename, PacketCallback callback) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(filename.c_str(), errbuf);
    
    if (!handle) {
        last_error_ = "Failed to open pcap file: " + std::string(errbuf);
        return false;
    }
    
    callback_ = callback;
    packet_counter_ = 0;
    
    // Read all packets from file
    struct pcap_pkthdr* header;
    const u_char* packet;
    int result;
    
    while ((result = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (result == 0) continue; // Timeout
        
        // Process packet using the same handler
        packetHandler((u_char*)this, header, packet);
    }
    
    if (result == -1) {
        last_error_ = "Error reading pcap file: " + std::string(pcap_geterr(handle));
        pcap_close(handle);
        return false;
    }
    
    pcap_close(handle);
    last_error_.clear();
    return true;
}

