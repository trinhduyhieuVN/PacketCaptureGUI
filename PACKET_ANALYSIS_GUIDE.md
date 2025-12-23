# 📚 Hướng Dẫn Phân Tích Packet - From Zero to Hero

## 🎯 Mục Lục

1. [Kiến Thức Cơ Bản](#kiến-thức-cơ-bản)
2. [OSI Model & TCP/IP](#osi-model--tcpip)
3. [Các Loại Protocol](#các-loại-protocol)
4. [Cách Đọc Packet](#cách-đọc-packet)
5. [Phân Tích Thực Tế](#phân-tích-thực-tế)
6. [Troubleshooting](#troubleshooting)

---

## 📖 Kiến Thức Cơ Bản

### Network Packet Là Gì?

**Packet** = Một "gói tin" dữ liệu được gửi qua mạng

```
┌─────────────────────────────────────┐
│  Headers  │  Payload (Data)  │ FCS │
└─────────────────────────────────────┘

Headers: Thông tin điều khiển (IP, Port, Protocol...)
Payload: Dữ liệu thực sự (webpage, file, message...)
FCS: Frame Check Sequence (kiểm tra lỗi)
```

### Tại Sao Cần Phân Tích Packet?

✅ **Debug network issues** - Tìm lỗi kết nối  
✅ **Security monitoring** - Phát hiện tấn công  
✅ **Performance tuning** - Tối ưu tốc độ  
✅ **Learning networking** - Hiểu cách Internet hoạt động  

---

## 🏗️ OSI Model & TCP/IP

### OSI 7 Layers (Mô hình lý thuyết)

```
Layer 7: Application  → HTTP, DNS, FTP
Layer 6: Presentation → Mã hóa, nén dữ liệu
Layer 5: Session      → Quản lý phiên
Layer 4: Transport    → TCP, UDP
Layer 3: Network      → IP, ICMP, ARP
Layer 2: Data Link    → Ethernet, WiFi
Layer 1: Physical     → Cáp, sóng radio
```

### TCP/IP Model (Thực tế sử dụng)

```
┌──────────────────────────┐
│  Application Layer       │ → HTTP, DNS, FTP
│  (Layer 7)               │
├──────────────────────────┤
│  Transport Layer         │ → TCP, UDP
│  (Layer 4)               │
├──────────────────────────┤
│  Internet Layer          │ → IP, ICMP, ARP
│  (Layer 3)               │
├──────────────────────────┤
│  Link Layer              │ → Ethernet
│  (Layer 2)               │
└──────────────────────────┘
```

### Packet Structure (Layer by Layer)

```
┌─────────────────────────────────────────────┐
│ Ethernet Header (Layer 2)                   │
│ - Source MAC: 00:11:22:33:44:55             │
│ - Dest MAC: AA:BB:CC:DD:EE:FF               │
│ - Type: 0x0800 (IPv4)                       │
├─────────────────────────────────────────────┤
│ IP Header (Layer 3)                         │
│ - Source IP: 192.168.1.100                  │
│ - Dest IP: 8.8.8.8                          │
│ - Protocol: 6 (TCP)                         │
├─────────────────────────────────────────────┤
│ TCP Header (Layer 4)                        │
│ - Source Port: 54321                        │
│ - Dest Port: 443 (HTTPS)                    │
│ - Flags: SYN, ACK                           │
├─────────────────────────────────────────────┤
│ Application Data (Layer 7)                  │
│ - HTTPS encrypted data                      │
└─────────────────────────────────────────────┘
```

---

## 🌐 Các Loại Protocol

### 1. 📡 **Ethernet (Layer 2)**

**Chức năng:** Truyền dữ liệu trong LAN (mạng nội bộ)

**Thông tin quan trọng:**
- **MAC Address:** Địa chỉ vật lý của card mạng (48-bit)
  - Format: `AA:BB:CC:DD:EE:FF`
  - VD: `00:1A:2B:3C:4D:5E`
- **EtherType:** Loại protocol bên trong
  - `0x0800` = IPv4
  - `0x0806` = ARP
  - `0x86DD` = IPv6

**Khi nào thấy:**
- Tất cả packets đều có Ethernet header
- Quan trọng khi troubleshoot LAN issues

---

### 2. 🔢 **IP - Internet Protocol (Layer 3)**

**Chức năng:** Định tuyến packet qua Internet

**IPv4 Address:**
- Format: `192.168.1.1` (32-bit, 4 octet)
- Classes:
  - **Class A:** 1.0.0.0 - 126.255.255.255 (Large networks)
  - **Class B:** 128.0.0.0 - 191.255.255.255 (Medium)
  - **Class C:** 192.0.0.0 - 223.255.255.255 (Small)
  - **Private IPs:**
    - `10.0.0.0/8`
    - `172.16.0.0/12`
    - `192.168.0.0/16`

**IP Header Fields:**

| Field | Ý Nghĩa | Giá Trị Thường Thấy |
|-------|---------|---------------------|
| **Version** | Phiên bản IP | 4 (IPv4) |
| **TTL** | Time To Live | 64, 128, 255 |
| **Protocol** | Loại transport | 6=TCP, 17=UDP, 1=ICMP |
| **Checksum** | Kiểm tra lỗi header | Auto-calculated |
| **Flags** | DF, MF | DF=Don't Fragment, MF=More Fragments |

**Ví dụ đọc IP packet:**
```
Source IP: 192.168.1.100 (Máy của bạn)
Dest IP: 142.250.185.46 (Google server)
TTL: 64 (Còn 64 hops để đến đích)
Protocol: TCP (Đây là TCP packet)
```

---

### 3. 🔗 **TCP - Transmission Control Protocol (Layer 4)**

**Chức năng:** Đảm bảo dữ liệu đến đích đầy đủ, đúng thứ tự

**Đặc điểm:**
- ✅ **Reliable** - Đảm bảo không mất data
- ✅ **Ordered** - Dữ liệu đến đúng thứ tự
- ✅ **Connection-oriented** - Cần thiết lập kết nối trước

**TCP Header Fields:**

| Field | Ý Nghĩa | Giải Thích |
|-------|---------|-----------|
| **Source Port** | Cổng nguồn | 1-65535, thường random |
| **Dest Port** | Cổng đích | 80=HTTP, 443=HTTPS, 22=SSH |
| **Sequence Number** | Số thứ tự | Để sắp xếp đúng thứ tự |
| **Ack Number** | Số xác nhận | "Tôi đã nhận đến byte thứ X" |
| **Flags** | Cờ điều khiển | SYN, ACK, FIN, RST... |
| **Window Size** | Kích thước cửa sổ | Flow control |

**TCP Flags (CỰC KỲ QUAN TRỌNG!):**

| Flag | Tên | Ý Nghĩa | Khi Nào Thấy |
|------|-----|---------|--------------|
| **SYN** | Synchronize | Yêu cầu kết nối | Bước 1 của 3-way handshake |
| **ACK** | Acknowledge | Xác nhận nhận được | Hầu hết các packets |
| **FIN** | Finish | Kết thúc kết nối | Khi đóng connection |
| **RST** | Reset | Hủy kết nối ngay | Lỗi hoặc firewall block |
| **PSH** | Push | Gửi dữ liệu ngay | HTTP request/response |
| **URG** | Urgent | Dữ liệu khẩn cấp | Rất hiếm thấy |

**TCP 3-Way Handshake (Thiết lập kết nối):**

```
Client                    Server
  │                          │
  │──────── SYN ────────────>│  "Xin chào, tôi muốn kết nối"
  │                          │
  │<────── SYN-ACK ──────────│  "OK, tôi đồng ý"
  │                          │
  │──────── ACK ────────────>│  "Được, bắt đầu thôi!"
  │                          │
  │ [Connection Established] │
```

**Ví dụ đọc TCP packet:**
```
Packet #1: [SYN]
→ Client muốn kết nối đến server
→ Seq=0 (bắt đầu)

Packet #2: [SYN-ACK]
→ Server chấp nhận
→ Seq=0, Ack=1

Packet #3: [ACK]
→ Client xác nhận
→ Seq=1, Ack=1
```

**Common TCP Ports:**

| Port | Service | Mục Đích |
|------|---------|----------|
| 20, 21 | FTP | File Transfer |
| 22 | SSH | Remote login (secure) |
| 23 | Telnet | Remote login (insecure) |
| 25 | SMTP | Email gửi đi |
| 80 | HTTP | Web không mã hóa |
| 443 | HTTPS | Web có mã hóa SSL/TLS |
| 3306 | MySQL | Database |
| 3389 | RDP | Remote Desktop |
| 8080 | HTTP-Alt | Web server thay thế |

---

### 4. 📦 **UDP - User Datagram Protocol (Layer 4)**

**Chức năng:** Gửi dữ liệu nhanh, không quan tâm mất mát

**Đặc điểm:**
- ⚡ **Fast** - Nhanh hơn TCP
- ❌ **Unreliable** - Có thể mất data
- 🔀 **Connectionless** - Không cần thiết lập kết nối

**Khi nào dùng UDP:**
- 🎮 Gaming (low latency quan trọng hơn)
- 📹 Video streaming (mất vài frame không sao)
- 🔊 VoIP (thoại qua mạng)
- 🌐 DNS (queries nhỏ, nhanh)

**UDP Header (Đơn giản hơn TCP):**

| Field | Ý Nghĩa |
|-------|---------|
| Source Port | Cổng nguồn |
| Dest Port | Cổng đích |
| Length | Độ dài packet |
| Checksum | Kiểm tra lỗi |

**Common UDP Ports:**

| Port | Service | Mục Đích |
|------|---------|----------|
| 53 | DNS | Domain name lookup |
| 67, 68 | DHCP | Cấp IP tự động |
| 123 | NTP | Đồng bộ thời gian |
| 161, 162 | SNMP | Network monitoring |
| 500 | IKE | VPN |

**Ví dụ đọc UDP packet:**
```
Source: 192.168.1.100:54321
Dest: 8.8.8.8:53 (DNS)
Length: 42 bytes
→ Đây là DNS query
```

---

### 5. 🔍 **DNS - Domain Name System**

**Chức năng:** Chuyển đổi tên miền → IP address

**DNS Query Flow:**
```
1. Bạn gõ: www.google.com
2. Browser → DNS query → 8.8.8.8
3. DNS response: 142.250.185.46
4. Browser connect đến IP đó
```

**DNS Record Types:**

| Type | Ý Nghĩa | Ví Dụ |
|------|---------|-------|
| **A** | IPv4 address | google.com → 142.250.185.46 |
| **AAAA** | IPv6 address | google.com → 2404:6800::200e |
| **CNAME** | Alias | www → example.com |
| **MX** | Mail server | mail.example.com |
| **TXT** | Text info | SPF, DKIM records |

**Cách đọc DNS packet:**

```
DNS Query:
  Transaction ID: 0x1234
  Questions: 1
  Query: www.google.com (Type A)
  
DNS Response:
  Transaction ID: 0x1234 (matching)
  Answers: 1
  www.google.com → 142.250.185.46
  TTL: 300 (cache 5 minutes)
```

**DNS Troubleshooting:**
```
Lỗi: "DNS_PROBE_FINISHED_NXDOMAIN"
→ Domain không tồn tại hoặc DNS server lỗi

Lỗi: "DNS timeout"
→ DNS server không phản hồi (firewall?)

Lỗi: "DNS hijacking"
→ DNS response bị thay đổi (malware)
```

---

### 6. 🌐 **HTTP - HyperText Transfer Protocol**

**Chức năng:** Truyền tải web pages

**HTTP Request Structure:**

```http
GET /index.html HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0
Accept: text/html
Connection: keep-alive
```

**HTTP Methods:**

| Method | Mục Đích | Example |
|--------|----------|---------|
| **GET** | Lấy dữ liệu | Load webpage |
| **POST** | Gửi dữ liệu | Submit form |
| **PUT** | Update dữ liệu | Update profile |
| **DELETE** | Xóa dữ liệu | Delete account |
| **HEAD** | Lấy header only | Check file size |

**HTTP Response Codes:**

| Code | Ý Nghĩa | Giải Thích |
|------|---------|-----------|
| **200** | OK | Success! |
| **301** | Moved Permanently | URL đã đổi vĩnh viễn |
| **302** | Found | Redirect tạm thời |
| **304** | Not Modified | Dùng cache |
| **400** | Bad Request | Request lỗi cú pháp |
| **401** | Unauthorized | Chưa đăng nhập |
| **403** | Forbidden | Không có quyền |
| **404** | Not Found | Không tìm thấy |
| **500** | Internal Server Error | Server bị lỗi |
| **502** | Bad Gateway | Proxy lỗi |
| **503** | Service Unavailable | Server quá tải |

**HTTP Headers Quan Trọng:**

```http
Host: www.example.com          → Domain đích
User-Agent: Chrome/120.0       → Browser type
Accept-Encoding: gzip          → Nén dữ liệu
Cookie: session=abc123         → Session info
Content-Type: text/html        → Loại dữ liệu
Content-Length: 1234           → Kích thước
Cache-Control: max-age=3600    → Cache 1h
```

**Cách đọc HTTP packet:**

```
HTTP Request:
  GET /search?q=networking HTTP/1.1
  Host: www.google.com
  → Tìm kiếm "networking" trên Google

HTTP Response:
  HTTP/1.1 200 OK
  Content-Type: text/html
  Content-Length: 5432
  → Server trả về HTML (5432 bytes)
```

**HTTP vs HTTPS:**
- **HTTP:** Không mã hóa (port 80) → Thấy rõ data
- **HTTPS:** Mã hóa SSL/TLS (port 443) → Chỉ thấy handshake

---

### 7. 📬 **ICMP - Internet Control Message Protocol**

**Chức năng:** Thông báo lỗi và kiểm tra kết nối

**ICMP Types:**

| Type | Name | Mục Đích | Command |
|------|------|----------|---------|
| **0** | Echo Reply | Phản hồi ping | `ping 8.8.8.8` |
| **3** | Dest Unreachable | Không đến được đích | Network error |
| **5** | Redirect | Đổi route | Router suggestion |
| **8** | Echo Request | Gửi ping | `ping` command |
| **11** | Time Exceeded | TTL = 0 | `tracert` |

**Ping Flow:**

```
You                     8.8.8.8
 │                         │
 │─── Echo Request (8) ───>│  id=1, seq=1
 │                         │
 │<── Echo Reply (0) ──────│  id=1, seq=1, time=20ms
 │                         │
 │─── Echo Request (8) ───>│  id=1, seq=2
 │                         │
 │<── Echo Reply (0) ──────│  id=1, seq=2, time=21ms
```

**Traceroute (tracert) - Tìm đường đi:**

```
tracert google.com

Hop 1: 192.168.1.1 (router)     - 1ms
Hop 2: 10.0.0.1 (ISP gateway)   - 5ms
Hop 3: 172.16.0.1 (ISP core)    - 10ms
...
Hop 10: 142.250.185.46 (Google) - 20ms
```

**ICMP Destination Unreachable Codes:**

| Code | Ý Nghĩa | Nguyên Nhân |
|------|---------|-------------|
| 0 | Net Unreachable | Không route được |
| 1 | Host Unreachable | Máy đích tắt |
| 3 | Port Unreachable | Service không chạy |
| 4 | Fragmentation Needed | MTU quá nhỏ |
| 13 | Admin Prohibited | Firewall block |

---

### 8. 🔄 **ARP - Address Resolution Protocol**

**Chức năng:** Tìm MAC address từ IP address (trong LAN)

**Tại sao cần ARP:**
- IP address: Định danh logic (192.168.1.100)
- MAC address: Định danh vật lý (AA:BB:CC:DD:EE:FF)
- LAN chỉ hiểu MAC, nên cần convert IP → MAC

**ARP Process:**

```
Tình huống: 192.168.1.100 muốn gửi data đến 192.168.1.200

Step 1: ARP Request (Broadcast)
  Sender: "Ai có IP 192.168.1.200? MAC của tôi là AA:BB:CC:DD:EE:FF"
  → Gửi broadcast đến tất cả máy trong LAN

Step 2: ARP Reply (Unicast)
  Target: "Tôi đây! MAC của tôi là 11:22:33:44:55:66"
  → Chỉ gửi lại cho máy hỏi

Step 3: Cache ARP
  192.168.1.100 lưu: 192.168.1.200 = 11:22:33:44:55:66
  → Lần sau không cần hỏi lại (trong vài phút)
```

**ARP Packet Fields:**

```
ARP Request:
  Operation: 1 (Request)
  Sender MAC: AA:BB:CC:DD:EE:FF
  Sender IP: 192.168.1.100
  Target MAC: 00:00:00:00:00:00 (unknown)
  Target IP: 192.168.1.200

ARP Reply:
  Operation: 2 (Reply)
  Sender MAC: 11:22:33:44:55:66
  Sender IP: 192.168.1.200
  Target MAC: AA:BB:CC:DD:EE:FF
  Target IP: 192.168.1.100
```

**ARP Commands:**

```powershell
# Xem ARP cache
arp -a

# Xóa ARP cache
arp -d

# Thêm static ARP entry
arp -s 192.168.1.100 AA-BB-CC-DD-EE-FF
```

**ARP Spoofing (Attack):**
```
Attacker giả mạo: "Tôi là 192.168.1.1 (router)"
→ Tất cả traffic đi qua attacker
→ Man-in-the-middle attack
```

---

## 🎓 Cách Đọc Packet Trong Tool

### Giao Diện Packet List

```
┌────────────────────────────────────────────────────────────┐
│ No. │ Time     │ Source      │ Dest        │ Protocol │ Info │
├────────────────────────────────────────────────────────────┤
│ 1   │ 10:30:15 │ 192.168.1.100│ 8.8.8.8   │ DNS      │ Query│
│ 2   │ 10:30:15 │ 8.8.8.8     │ 192.168.1.100│ DNS    │ Response│
│ 3   │ 10:30:16 │ 192.168.1.100│ 142.250... │ TCP     │ SYN  │
│ 4   │ 10:30:16 │ 142.250...  │ 192.168.1.100│ TCP    │ SYN-ACK│
└────────────────────────────────────────────────────────────┘
```

### Đọc Từng Cột:

**1. No. (Number)**
- Số thứ tự packet
- Bắt đầu từ 1
- Dùng để reference ("check packet #123")

**2. Time**
- Thời gian capture
- Format: HH:MM:SS hoặc timestamp
- Giúp phân tích timeline

**3. Source (Nguồn)**
- IP address hoặc MAC address của người gửi
- 192.168.1.x = Local network
- Public IP = Internet

**4. Destination (Đích)**
- IP/MAC của người nhận
- Broadcast: 255.255.255.255
- Multicast: 224.0.0.0/4

**5. Protocol**
- Loại giao thức: TCP, UDP, ICMP, ARP, DNS, HTTP
- Màu sắc khác nhau:
  - 🟢 TCP = Xanh lá
  - 🟡 UDP = Vàng
  - 🟠 ICMP = Cam
  - 🟣 ARP = Tím

**6. Info**
- Tóm tắt nội dung packet
- VD: "GET /index.html", "Echo Request", "SYN-ACK"

---

## 🔬 Phân Tích Thực Tế

### Scenario 1: Browse Website (HTTP)

**Flow hoàn chỉnh:**

```
Bạn gõ: http://example.com

Packet #1: DNS Query
  Source: 192.168.1.100:54321 → 8.8.8.8:53
  Protocol: DNS
  Info: "Query: example.com (Type A)"
  → Hỏi IP của example.com

Packet #2: DNS Response
  Source: 8.8.8.8:53 → 192.168.1.100:54321
  Protocol: DNS
  Info: "Response: 93.184.216.34"
  → Google DNS trả lời

Packet #3: TCP SYN
  Source: 192.168.1.100:54322 → 93.184.216.34:80
  Protocol: TCP
  Flags: [SYN]
  Info: "54322 → 80 [SYN] Seq=0"
  → Xin kết nối đến web server

Packet #4: TCP SYN-ACK
  Source: 93.184.216.34:80 → 192.168.1.100:54322
  Protocol: TCP
  Flags: [SYN-ACK]
  Info: "80 → 54322 [SYN-ACK] Seq=0 Ack=1"
  → Server chấp nhận

Packet #5: TCP ACK
  Source: 192.168.1.100:54322 → 93.184.216.34:80
  Protocol: TCP
  Flags: [ACK]
  Info: "54322 → 80 [ACK] Seq=1 Ack=1"
  → Kết nối thành công!

Packet #6: HTTP GET Request
  Source: 192.168.1.100:54322 → 93.184.216.34:80
  Protocol: HTTP
  Info: "GET / HTTP/1.1"
  → Yêu cầu trang chủ

Packet #7: HTTP Response
  Source: 93.184.216.34:80 → 192.168.1.100:54322
  Protocol: HTTP
  Info: "HTTP/1.1 200 OK"
  → Server gửi HTML về

Packet #8: TCP FIN
  Source: 192.168.1.100:54322 → 93.184.216.34:80
  Protocol: TCP
  Flags: [FIN-ACK]
  Info: "54322 → 80 [FIN-ACK]"
  → Đóng kết nối
```

**Timeline:**
```
0ms:    DNS Query
20ms:   DNS Response (20ms latency)
25ms:   TCP SYN
45ms:   TCP SYN-ACK (20ms RTT)
45ms:   TCP ACK (0ms, cùng lúc gửi request)
45ms:   HTTP GET
85ms:   HTTP Response (40ms server processing)
90ms:   TCP FIN
```

---

### Scenario 2: Ping Google

```
Command: ping 8.8.8.8

Packet #1: ICMP Echo Request
  Source: 192.168.1.100 → 8.8.8.8
  Protocol: ICMP
  Type: 8 (Echo Request)
  Identifier: 1
  Sequence: 1
  Data: 32 bytes
  → Gửi ping

Packet #2: ICMP Echo Reply
  Source: 8.8.8.8 → 192.168.1.100
  Protocol: ICMP
  Type: 0 (Echo Reply)
  Identifier: 1
  Sequence: 1
  TTL: 117 (Google còn xa)
  Time: 20ms
  → Google phản hồi

Packet #3: ICMP Echo Request
  Sequence: 2
  → Ping lần 2

Packet #4: ICMP Echo Reply
  Sequence: 2
  Time: 21ms
  → Reply lần 2
```

**Phân tích:**
- ✅ RTT (Round Trip Time): 20-21ms → Tốt
- ✅ TTL: 117 → Đi qua ~10 hops (128 - 117)
- ✅ No packet loss → Kết nối ổn định

---

### Scenario 3: Failed Connection (Port Closed)

```
Bạn thử: telnet example.com 23

Packet #1: TCP SYN
  Source: 192.168.1.100:54323 → 93.184.216.34:23
  Flags: [SYN]
  → Xin kết nối port 23

Packet #2: TCP RST-ACK
  Source: 93.184.216.34:23 → 192.168.1.100:54323
  Flags: [RST-ACK]
  → Server từ chối (port đóng)

Kết luận: Port 23 (Telnet) không mở trên server
```

---

### Scenario 4: HTTPS (Encrypted)

```
Browse: https://www.google.com

Packet #1-2: DNS Query/Response
  → Giống HTTP

Packet #3-5: TCP 3-Way Handshake
  → Giống HTTP

Packet #6: TLS Client Hello
  Source: 192.168.1.100 → 142.250.185.46:443
  Protocol: TLS
  Info: "Client Hello (TLS 1.3)"
  → Bắt đầu handshake SSL

Packet #7: TLS Server Hello
  Source: 142.250.185.46 → 192.168.1.100
  Protocol: TLS
  Info: "Server Hello, Certificate"
  → Server gửi certificate

Packet #8-10: TLS Key Exchange
  → Trao đổi encryption keys

Packet #11+: TLS Application Data
  Protocol: TLS
  Info: "Application Data (Encrypted)"
  → Data đã mã hóa, KHÔNG ĐỌC ĐƯỢC!
```

**Lưu ý:** HTTPS chỉ thấy được:
- ✅ IP addresses
- ✅ Handshake process
- ❌ KHÔNG thấy URL, data, headers

---

## 🛠️ Troubleshooting Thực Tế

### Problem 1: Website Không Load

**Step 1: Check DNS**
```
Filter: dns
Tìm: Query cho domain bạn đang truy cập
```

✅ **Có DNS Response với IP?** → DNS OK  
❌ **Không có Response?** → DNS server lỗi

```powershell
# Fix: Đổi DNS sang Google
ipconfig /flushdns
# Set DNS: 8.8.8.8
```

---

**Step 2: Check TCP Connection**
```
Filter: tcp.flags.syn == 1
Tìm: SYN packet đến IP của website
```

✅ **Có SYN-ACK?** → Connection OK  
❌ **Có RST?** → Port closed/Firewall block  
❌ **No response?** → Server down/Network issue

---

**Step 3: Check HTTP**
```
Filter: http
Tìm: GET request
```

✅ **Có HTTP 200?** → Server OK  
❌ **HTTP 404?** → URL sai  
❌ **HTTP 500?** → Server error  
❌ **No HTTP?** → SSL/TLS issue (nếu HTTPS)

---

### Problem 2: Slow Internet

**Step 1: Check Latency**
```
Filter: icmp
Ping 8.8.8.8
Xem Time field trong ICMP Reply
```

- < 20ms: Excellent
- 20-50ms: Good
- 50-100ms: Fair
- \> 100ms: Slow
- \> 500ms: Very slow

---

**Step 2: Check Retransmissions**
```
Filter: tcp.analysis.retransmission
```

❌ **Nhiều retransmission?** → Packet loss, network congestion

---

**Step 3: Check Window Size**
```
Filter: tcp.window_size < 1000
```

❌ **Window size nhỏ?** → Receiver quá tải, slow down

---

### Problem 3: Connection Timeout

**Triệu chứng:**
```
No SYN-ACK sau khi gửi SYN
```

**Nguyên nhân:**
1. **Firewall block** → No response
2. **Server down** → No response  
3. **Route issue** → ICMP Destination Unreachable
4. **ISP block** → Silent drop

**Debug:**
```
1. Ping IP → Check host alive
2. Tracert IP → Check routing
3. Telnet IP Port → Check port open
4. Check firewall rules
```

---

### Problem 4: ARP Issues

**Triệu chứng:**
```
Không connect được máy trong LAN
```

**Check ARP:**
```powershell
arp -a
# Look for:
# - Missing entries
# - Duplicate MACs (ARP poisoning!)
```

**Fix:**
```powershell
arp -d        # Clear cache
ipconfig /release
ipconfig /renew
```

---

## 📊 BPF Filter Examples

### Basic Filters

```
tcp                    → Chỉ TCP packets
udp                    → Chỉ UDP packets
icmp                   → Chỉ ICMP packets
arp                    → Chỉ ARP packets

tcp port 80            → HTTP traffic
tcp port 443           → HTTPS traffic
udp port 53            → DNS traffic

host 192.168.1.1       → Traffic từ/đến IP này
src host 192.168.1.1   → Traffic từ IP này
dst host 192.168.1.1   → Traffic đến IP này

net 192.168.1.0/24     → Toàn bộ subnet
```

### Advanced Filters

```
tcp[tcpflags] & tcp-syn != 0   → Chỉ SYN packets
tcp[tcpflags] & tcp-fin != 0   → Chỉ FIN packets

port 80 or port 443            → HTTP hoặc HTTPS
host 192.168.1.1 and port 22   → SSH đến/từ host

not broadcast and not multicast → Unicast only
greater 1000                    → Packets > 1000 bytes
```

### Troubleshooting Filters

```
# Tìm errors
icmp[icmptype] == 3            → Destination Unreachable
tcp.flags.reset == 1           → RST packets

# Tìm slow traffic
tcp.analysis.ack_rtt > 0.1     → High latency (>100ms)
tcp.analysis.retransmission    → Retransmitted packets

# Tìm specific traffic
http.request.method == "POST"  → POST requests only
dns.qry.name contains "google" → DNS queries for Google
```

---

## 🎯 Tổng Kết

### Checklist Phân Tích Packet

**Level 1: Beginner**
- [ ] Nhận biết được protocol (TCP, UDP, ICMP)
- [ ] Đọc được Source/Dest IP
- [ ] Đọc được Port numbers
- [ ] Hiểu TCP flags cơ bản (SYN, ACK, FIN)

**Level 2: Intermediate**
- [ ] Phân biệt được DNS, HTTP, HTTPS
- [ ] Đọc được HTTP headers
- [ ] Hiểu TCP 3-way handshake
- [ ] Trace được flow của 1 connection

**Level 3: Advanced**
- [ ] Phân tích được performance issues
- [ ] Debug được network errors
- [ ] Dùng thành thạo BPF filters
- [ ] Phát hiện được security issues

---

### Resources Để Học Thêm

**Websites:**
- 📚 https://www.cloudflare.com/learning/ - Networking basics
- 📚 https://wiki.wireshark.org/ - Wireshark documentation
- 📚 https://packetlife.net/ - Cheat sheets & tutorials

**Books:**
- 📖 "Computer Networking: A Top-Down Approach"
- 📖 "TCP/IP Illustrated" - W. Richard Stevens
- 📖 "Wireshark Network Analysis"

**Practice:**
- 🎮 https://overthewire.org/ - Network challenges
- 🎮 Capture your own traffic và analyze
- 🎮 https://www.wireshark.org/download.html - Sample captures

---

**🎊 Chúc bạn thành công trong việc phân tích packets!**

_"The best way to learn networking is to see it in action!"_
