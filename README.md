# 🌐 Network Packet Analyzer GUI

<div align="center">

**Professional Network Packet Capture & Analysis Tool**

Modern Wireshark-style interface built with Dear ImGui + OpenGL

[![Platform](https://img.shields.io/badge/Platform-Windows-blue.svg)](https://www.microsoft.com/windows)
[![C++](https://img.shields.io/badge/C++-17-00599C.svg)](https://isocpp.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Build](https://img.shields.io/badge/Build-CMake-064F8C.svg)](https://cmake.org/)

</div>

---

## 📖 Giới thiệu

**PacketCaptureGUI** là công cụ phân tích gói tin mạng (Network Packet Analyzer) chuyên nghiệp với giao diện đồ họa hiện đại, được phát triển bằng C++ và Dear ImGui. Ứng dụng cho phép bắt, hiển thị và phân tích chi tiết các gói tin mạng trên các giao diện mạng (Network Interfaces) của Windows.

### ✨ Tính năng chính

#### 🎨 **Giao diện chuyên nghiệp**
- **Wireshark-style UI**: Layout chuẩn công nghiệp với Title Bar, Control Panel, Packet List, Packet Details, Status Bar
- **Dark/Light Theme**: Hỗ trợ chuyển đổi theme sáng/tối
- **Large UI Elements**: Font 20px, buttons 220x55px, dễ thao tác
- **Responsive Design**: Tự động điều chỉnh theo kích thước cửa sổ
- **Protocol Color Coding**: Màu sắc phân biệt các protocol (TCP=xanh lá, UDP=vàng, ICMP=cam, ARP=tím)

#### 📡 **Packet Capture Engine**
- **Multi-Protocol Support**: Ethernet, IPv4, TCP, UDP, ICMP, ARP, HTTP, DNS
- **Real-time Capture**: Bắt và hiển thị packets ngay lập tức
- **Deep Packet Inspection**: Phân tích chi tiết từng layer của protocol stack
- **Raw Data View**: Hex dump với ASCII representation

#### 🔍 **Protocol Analysis** 
- **Ethernet II**: Source/Destination MAC, EtherType với tên giao thức
- **IPv4**: Version, IHL, TOS, Total Length, Identification, Flags (DF/MF), Fragment Offset, TTL, Protocol, Checksum, Source/Dest IP
- **TCP**: Ports, Sequence/Acknowledgment numbers, Data Offset, **Full Flags** (SYN/ACK/FIN/RST/PSH/URG/ECE/CWR), Window Size, Checksum
- **UDP**: Ports, Length, Checksum
- **ICMP**: Type với tên (Echo Request/Reply, Destination Unreachable, etc.), Code, Identifier, Sequence
- **ARP**: Operation (Request/Reply), Sender/Target MAC & IP
- **HTTP**: Request (Method, URI, Version, Host, User-Agent), Response (Status Code, Content-Type)
- **DNS**: Transaction ID, Query/Response, Questions/Answers count, Query names, Response IPs

#### 📊 **Statistics & Monitoring**
- **Protocol Distribution**: Real-time progress bars cho TCP/UDP/ICMP/ARP traffic
- **Live Packet Counter**: Đếm số packets đã capture
- **Capture Status**: Live indicator hiển thị trạng thái capture
- **Performance Monitoring**: Theo dõi throughput và packet rate

#### 🎯 **Filtering & Search**
- **IP Address Filter**: Lọc packets theo địa chỉ IP (source hoặc destination)
- **Protocol Filter**: Lọc theo loại protocol (TCP, UDP, ICMP, ARP, HTTP, DNS)
- **Real-time Filtering**: Áp dụng filter ngay lập tức trên packet list

---

## 🚀 Hướng dẫn cài đặt

### 📋 Yêu cầu hệ thống

#### **Hệ điều hành**
- Windows 10 (64-bit) hoặc Windows 11
- Quyền Administrator (bắt buộc để capture packets)

#### **Công cụ phát triển**
- **Visual Studio 2022** (Community/Professional/Enterprise)
  - Workload: "Desktop development with C++"
  - MSVC v143 compiler hoặc mới hơn
- **CMake 3.10** hoặc mới hơn
  - Download: https://cmake.org/download/

#### **Runtime Dependencies**
- **Npcap 1.79+** (bắt buộc)
  - Download Runtime: https://npcap.com/#download
  - Cài đặt với tùy chọn "Install Npcap in WinPcap API-compatible Mode"

#### **SDK Dependencies**
- **Npcap SDK 1.13** (cần khi build)
  - Download: https://npcap.com/dist/npcap-sdk-1.13.zip
  - Giải nén vào `C:\npcap-sdk\`
  - Cấu trúc thư mục:
    ```
    C:\npcap-sdk\
    ├── Include\
    │   ├── pcap.h
    │   └── ...
    └── Lib\
        └── x64\
            └── wpcap.lib
    ```

#### **Graphics**
- OpenGL 3.3+ compatible GPU
- Updated graphics drivers

---

## 📥 Clone dự án

```bash
# Clone repository từ GitHub
git clone https://github.com/trinhduyhieuVN/PacketCaptureGUI.git

# Di chuyển vào thư mục dự án
cd PacketCaptureGUI
```

---

## 📂 Cấu trúc dự án

```
PacketCaptureGUI/
│
├── src/                          # Source code
│   ├── main.cpp                  # Main application & ImGui rendering
│   ├── packet_capture.h          # Packet capture engine header
│   ├── packet_capture.cpp        # Packet capture implementation (~680 lines)
│   ├── packet_data.h             # Data structures cho packets & protocols
│   └── packet_buffer.h           # Thread-safe circular buffer
│
├── build/                        # Build artifacts (tạo bởi CMake)
│   ├── bin/Release/
│   │   └── PacketCaptureGUI.exe # Executable file
│   └── external/                 # Auto-downloaded dependencies
│       ├── imgui/
│       └── glfw/
│
├── test_capture.cpp              # Simple test tool để verify pcap
├── test_devices.cpp              # Tool để list network interfaces
│
├── CMakeLists.txt                # CMake build configuration
├── README.md                     # Tài liệu này
└── .gitignore                    # Git ignore rules

Tự động download khi build:
├── Dear ImGui v1.90.1+           # GUI framework
└── GLFW 3.3.9                    # Window/input handling
```

### 📄 Mô tả các file chính

| File | Dòng code | Mô tả |
|------|-----------|-------|
| `main.cpp` | ~800 | UI rendering, window management, ImGui layout |
| `packet_capture.cpp` | ~680 | Packet capture engine, protocol parsing logic |
| `packet_data.h` | ~200 | Structures cho Ethernet, IPv4, TCP, UDP, HTTP, DNS, etc. |
| `packet_buffer.h` | ~50 | Thread-safe packet buffer với mutex |

---

## 🛠️ Build dự án

### Bước 1: Mở PowerShell/Command Prompt

```powershell
# Di chuyển vào thư mục dự án
cd PacketCaptureGUI
```

### Bước 2: Tạo build directory

```powershell
mkdir build
cd build
```

### Bước 3: Configure với CMake

```powershell
# Generate Visual Studio 2022 solution
cmake .. -G "Visual Studio 17 2022" -A x64
```

**Lưu ý:** CMake sẽ tự động:
- Download Dear ImGui từ GitHub
- Download GLFW từ GitHub  
- Link với Npcap SDK tại `C:\npcap-sdk\`

### Bước 4: Build

```powershell
# Build Release version
cmake --build . --config Release

# HOẶC build Debug version (có debug symbols)
cmake --build . --config Debug
```

### Bước 5: Kiểm tra output

```powershell
# Executable sẽ được tạo tại:
.\bin\Release\PacketCaptureGUI.exe
```

### ⚠️ Troubleshooting

**Lỗi: "Cannot find pcap.h"**
```powershell
# Kiểm tra Npcap SDK đã cài đúng vị trí
dir C:\npcap-sdk\Include\pcap.h
```

**Lỗi: "Cannot open wpcap.lib"**
```powershell
# Kiểm tra lib file
dir C:\npcap-sdk\Lib\x64\wpcap.lib
```

**Lỗi build CMake:**
```powershell
# Xóa build directory và thử lại
cd ..
rmdir -Recurse -Force build
mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

---

## ▶️ Chạy ứng dụng

### 🔐 Chạy với quyền Administrator (BẮT BUỘC)

**Cách 1: PowerShell**
```powershell
cd build\bin\Release
Start-Process .\PacketCaptureGUI.exe -Verb RunAs
```

**Cách 2: File Explorer**
- Right-click vào `PacketCaptureGUI.exe`
- Chọn "Run as administrator"

**Cách 3: Tạo shortcut với admin rights**
- Right-click vào exe → Create shortcut
- Right-click shortcut → Properties → Advanced
- Check "Run as administrator"

### ⚡ Test nhanh với tool đơn giản

Để test xem Npcap có hoạt động không:

```powershell
# Compile test tool
cd PacketCaptureGUI
g++ test_capture.cpp -o test_capture.exe -I"C:\npcap-sdk\Include" -L"C:\npcap-sdk\Lib\x64" -lwpcap -lws2_32

# Chạy với quyền admin
Start-Process .\test_capture.exe -Verb RunAs
```

---

## 📘 Hướng dẫn sử dụng

### 1️⃣ **Khởi động ứng dụng**

<img src="https://img.shields.io/badge/Step-1-blue" alt="Step 1"/>

- Chạy `PacketCaptureGUI.exe` với quyền Administrator
- Giao diện sẽ hiển thị với theme tối (Dark theme) mặc định

### 2️⃣ **Chọn Network Interface**

<img src="https://img.shields.io/badge/Step-2-blue" alt="Step 2"/>

**Vị trí:** Control Panel (bên trái) → NETWORK INTERFACE

**Các interface phổ biến:**
- ✅ **MediaTek Wi-Fi / Realtek Ethernet**: Interface thực đang sử dụng (CHỌN CÁI NÀY)
- ⚠️ **WAN Miniport**: Thường không có traffic
- ⚠️ **Virtual Adapter**: Adapter ảo, ít traffic
- ℹ️ **Loopback**: Chỉ traffic localhost (127.0.0.1)

**Lưu ý:** 
- Chọn interface đang kết nối Internet (WiFi hoặc Ethernet)
- Nếu không chắc, thử từng interface

### 3️⃣ **Thiết lập Filter (Tùy chọn)**

<img src="https://img.shields.io/badge/Step-3-blue" alt="Step 3"/>

**Vị trí:** Control Panel → CAPTURE FILTER

**IP Address Filter:**
```
192.168.1.1          # Chỉ packets có IP này (source hoặc dest)
8.8.8.8              # Google DNS
```

**Protocol Filter:**
```
TCP                  # Chỉ hiển thị TCP packets
UDP                  # Chỉ hiển thị UDP packets
HTTP                 # Chỉ hiển thị HTTP traffic
DNS                  # Chỉ hiển thị DNS queries/responses
ICMP                 # Chỉ hiển thị ICMP (ping)
```

### 4️⃣ **Bắt đầu Capture**

<img src="https://img.shields.io/badge/Step-4-green" alt="Step 4"/>

**Vị trí:** Control Panel → CAPTURE CONTROL

- Click nút **START CAPTURE** (màu xanh lá)
- Status bar (dưới cùng) sẽ hiển thị "Capturing on [Interface name]"
- Live indicator sẽ chuyển sang màu xanh lá với nhịp đập

### 5️⃣ **Tạo Network Traffic**

<img src="https://img.shields.io/badge/Step-5-blue" alt="Step 5"/>

Để thấy packets xuất hiện:

**Cách 1: Mở trình duyệt web**
```
- Mở Chrome/Edge
- Truy cập https://google.com
- Sẽ thấy HTTP/HTTPS packets
```

**Cách 2: Ping**
```powershell
# Mở PowerShell mới
ping google.com
ping 8.8.8.8
```
→ Sẽ thấy ICMP packets (Echo Request/Reply)

**Cách 3: DNS Lookup**
```powershell
nslookup google.com
```
→ Sẽ thấy DNS packets (Query/Response)

### 6️⃣ **Xem Packet List**

<img src="https://img.shields.io/badge/Step-6-blue" alt="Step 6"/>

**Vị trí:** Cửa sổ giữa (Packet List Table)

**Các cột trong bảng:**

| Cột | Mô tả |
|-----|-------|
| **No.** | Số thứ tự packet |
| **Time** | Timestamp (giây) |
| **Source** | Địa chỉ IP nguồn |
| **Destination** | Địa chỉ IP đích |
| **Protocol** | Loại protocol (TCP/UDP/ICMP/ARP/HTTP/DNS) |
| **Length** | Kích thước packet (bytes) |
| **Src Port** | Port nguồn (TCP/UDP) |
| **Dst Port** | Port đích (TCP/UDP) |
| **Info** | Thông tin tóm tắt |

**Màu sắc protocol:**
- 🟢 **TCP**: Màu xanh lá nhạt
- 🟡 **UDP**: Màu vàng nhạt
- 🟠 **ICMP**: Màu cam nhạt
- 🟣 **ARP**: Màu tím nhạt
- 🔵 **HTTP**: Màu xanh dương
- 🔷 **DNS**: Màu cyan

### 7️⃣ **Xem Packet Details**

<img src="https://img.shields.io/badge/Step-7-blue" alt="Step 7"/>

**Click vào bất kỳ packet nào** trong Packet List

**Panel chi tiết sẽ hiển thị:**

#### **Frame Information**
- Packet Number, Arrival Time, Frame Length

#### **Ethernet II** (Layer 2)
- Destination MAC: `AA:BB:CC:DD:EE:FF`
- Source MAC: `11:22:33:44:55:66`
- Type: `0x0800 (IPv4)` hoặc `0x0806 (ARP)`

#### **Internet Protocol Version 4** (Layer 3)
- Version: `4`
- Header Length: `20 bytes`
- Total Length: `60 bytes`
- Identification: `0x1234`
- Flags: `DF=1, MF=0` (Don't Fragment, More Fragments)
- Time to Live: `64`
- Protocol: `TCP (6)` hoặc `UDP (17)`
- Header Checksum: `0xABCD`
- Source IP: `192.168.1.100`
- Destination IP: `8.8.8.8`

#### **Transmission Control Protocol** (Layer 4 - TCP)
- Source Port: `54321`
- Destination Port: `443` (HTTPS)
- Sequence Number: `123456789`
- Acknowledgment Number: `987654321`
- Flags: `[SYN ACK PSH]`
  - Individual flags với màu sắc:
    - 🟢 **SYN**: Synchronize (thiết lập kết nối)
    - 🟢 **ACK**: Acknowledgment
    - 🔵 **PSH**: Push (gửi data ngay)
    - 🟠 **FIN**: Finish (đóng kết nối)
    - 🔴 **RST**: Reset (hủy kết nối)
    - 🟡 **URG**: Urgent
- Window Size: `65535`
- Checksum: `0x1234`

#### **User Datagram Protocol** (Layer 4 - UDP)
- Source Port: `53` (DNS)
- Destination Port: `12345`
- Length: `100 bytes`
- Checksum: `0x5678`

#### **HyperText Transfer Protocol** (Application Layer)
**HTTP Request:**
- Method: `GET`
- URI: `/index.html`
- Version: `HTTP/1.1`
- Host: `example.com`
- User-Agent: `Mozilla/5.0...`

**HTTP Response:**
- Version: `HTTP/1.1`
- Status Code: `200`
- Status: `OK`
- Content-Type: `text/html`

#### **Domain Name System** (Application Layer)
**DNS Query:**
- Transaction ID: `0x1234`
- Type: `Query`
- Questions: `1`
- Queries:
  - `google.com`

**DNS Response:**
- Type: `Response`
- Answers: `1`
- Responses:
  - `142.250.185.46` (IP của google.com)

#### **Hex Dump** (Panel phải)
```
0000  ff ff ff ff ff ff 00 11  22 33 44 55 08 00 45 00   ........"3DU..E.
0010  00 3c 12 34 40 00 40 06  ab cd c0 a8 01 64 08 08   .<.4@.@......d..
0020  08 08 d4 31 01 bb 12 34  56 78 9a bc de f0 80 18   ...1...4Vx......
```
- **Cột 1**: Offset (hex)
- **Cột 2-3**: Hex bytes (16 bytes/dòng)
- **Cột 4**: ASCII representation

### 8️⃣ **Thống kê Real-time**

<img src="https://img.shields.io/badge/Step-8-blue" alt="Step 8"/>

**Vị trí:** Control Panel → PROTOCOL DISTRIBUTION

**Progress bars hiển thị tỷ lệ:**
- 📊 TCP: `45%` ████████░░
- 📊 UDP: `30%` ██████░░░░
- 📊 ICMP: `15%` ███░░░░░░░
- 📊 ARP: `10%` ██░░░░░░░░

### 9️⃣ **Dừng Capture**

<img src="https://img.shields.io/badge/Step-9-red" alt="Step 9"/>

- Click nút **STOP CAPTURE** (màu đỏ)
- Live indicator tắt
- Packets vẫn giữ trong buffer để xem lại

### 🔟 **Xóa Packets**

<img src="https://img.shields.io/badge/Step-10-grey" alt="Step 10"/>

- Click nút **CLEAR ALL** (màu xám)
- Xóa toàn bộ packets và reset thống kê
- Không ảnh hưởng đến capture đang chạy

### 1️⃣1️⃣ **Chuyển Theme**

<img src="https://img.shields.io/badge/Step-11-blue" alt="Step 11"/>

**Vị trí:** Title Bar (góc phải trên)

- Click nút **Dark** / **Light**
- Giao diện chuyển đổi theme ngay lập tức

---

## 🎓 Ví dụ sử dụng

### Ví dụ 1: Phân tích HTTP Request

1. Start capture trên WiFi interface
2. Mở browser → truy cập http://example.com
3. Trong Packet List, tìm packet màu xanh dương (HTTP)
4. Click vào packet
5. Packet Details sẽ hiển thị:
   ```
   HTTP Request
   Method: GET
   URI: /
   Host: example.com
   User-Agent: Mozilla/5.0...
   ```

### Ví dụ 2: Theo dõi DNS Query

1. Set Protocol Filter = `DNS`
2. Start capture
3. Mở PowerShell: `nslookup github.com`
4. Sẽ thấy 2 packets:
   - **DNS Query**: `github.com`
   - **DNS Response**: `140.82.121.4` (IP của GitHub)

### Ví dụ 3: Phân tích TCP Handshake

1. Clear all packets
2. Start capture
3. Mở browser → truy cập https://google.com
4. Trong Packet List, tìm 3 packets đầu tiên với cùng port:
   ```
   Packet 1: [SYN]           # Client → Server
   Packet 2: [SYN ACK]       # Server → Client  
   Packet 3: [ACK]           # Client → Server
   ```
   → Đây là **3-way handshake** của TCP!

### Ví dụ 4: Chẩn đoán Network Issue

**Tình huống:** Website không load được

1. Set IP Filter = địa chỉ IP của website
2. Start capture
3. Reload website
4. Kiểm tra:
   - Có TCP SYN packets không? → Kiểm tra firewall
   - Có nhận SYN-ACK không? → Kiểm tra server
   - Có HTTP Response không? → Kiểm tra web server
   - Response code là gì? → 200 OK / 404 Not Found / 500 Error

---

## 🔧 Advanced Usage

### Phím tắt

| Phím | Chức năng |
|------|-----------|
| `Page Up/Down` | Scroll packet list nhanh |
| `Home` | Về packet đầu tiên |
| `End` | Về packet cuối cùng |
| `Ctrl + Mouse Wheel` | Zoom in/out fonts |

### Tips & Tricks

**1. Capture traffic của một ứng dụng cụ thể:**
- Xác định port của ứng dụng (Task Manager → Details → Right-click → Properties)
- Set Protocol Filter theo port trong Packet Details

**2. Giảm packet overload:**
- Sử dụng IP Filter để chỉ xem traffic của một server
- Sử dụng Protocol Filter để loại bỏ noise (ARP, ICMP)

**3. Phân tích slow connection:**
- Xem TCP Window Size → nhỏ = congestion
- Xem retransmissions (duplicate Seq numbers)
- Xem Round-Trip Time (thời gian giữa SYN và SYN-ACK)

---

## 🐛 Troubleshooting

### Vấn đề: Không capture được packet nào

**Nguyên nhân & Giải pháp:**

1. **Không chạy với quyền Admin**
   ```
   → Right-click exe → Run as administrator
   ```

2. **Chọn sai interface**
   ```
   → Chọn WiFi/Ethernet adapter thực (không phải WAN Miniport)
   → Thử từng interface trong dropdown
   ```

3. **Không có network traffic**
   ```
   → Mở browser hoặc ping google.com
   → Kiểm tra internet connection
   ```

4. **Npcap service không chạy**
   ```powershell
   # Kiểm tra service
   Get-Service npcap
   
   # Start service nếu cần
   Start-Service npcap
   ```

5. **Npcap chưa cài đặt**
   ```
   → Download & install từ https://npcap.com
   → Chọn "WinPcap API-compatible Mode" khi cài
   ```

### Vấn đề: Build lỗi

**Lỗi: "pcap.h not found"**
```powershell
# Cài Npcap SDK vào đúng vị trí
# Download: https://npcap.com/dist/npcap-sdk-1.13.zip
# Giải nén vào C:\npcap-sdk\
```

**Lỗi: "Cannot find CMakeLists.txt"**
```powershell
# Đảm bảo đang ở thư mục build/
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
```

**Lỗi: "MSBuild not found"**
```
→ Cài Visual Studio 2022 với workload "Desktop development with C++"
```

### Vấn đề: UI quá nhỏ/lớn

```cpp
// Trong main.cpp, tìm dòng:
io.FontGlobalScale = 1.6f;

// Thay đổi giá trị:
io.FontGlobalScale = 1.0f;  // Nhỏ hơn
io.FontGlobalScale = 2.0f;  // Lớn hơn
```

### Vấn đề: Crash khi chạy

1. **Kiểm tra OpenGL support:**
   ```
   → Update GPU drivers
   → Kiểm tra GPU hỗ trợ OpenGL 3.3+
   ```

2. **Kiểm tra dependencies:**
   ```powershell
   # Trong build/bin/Release/, cần có:
   - PacketCaptureGUI.exe
   - glfw3.dll (nếu dynamic link)
   ```

3. **Chạy từ command line để xem error message:**
   ```powershell
   cd build\bin\Release
   .\PacketCaptureGUI.exe
   # Xem console output
   ```

---

## 📚 Kiến thức liên quan

### Protocols được hỗ trợ

#### **Layer 2 - Data Link**
- **Ethernet II**: Frame format phổ biến nhất trong LAN

#### **Layer 3 - Network**  
- **IPv4**: Internet Protocol version 4
- **ARP**: Address Resolution Protocol (map IP → MAC)
- **ICMP**: Internet Control Message Protocol (ping, traceroute)

#### **Layer 4 - Transport**
- **TCP**: Transmission Control Protocol (reliable, connection-oriented)
- **UDP**: User Datagram Protocol (fast, connectionless)

#### **Layer 7 - Application**
- **HTTP**: HyperText Transfer Protocol (web traffic)
- **DNS**: Domain Name System (name resolution)

### Port numbers phổ biến

| Port | Protocol | Service |
|------|----------|---------|
| 20-21 | TCP | FTP |
| 22 | TCP | SSH |
| 23 | TCP | Telnet |
| 25 | TCP | SMTP |
| 53 | UDP/TCP | DNS |
| 67-68 | UDP | DHCP |
| 80 | TCP | HTTP |
| 110 | TCP | POP3 |
| 143 | TCP | IMAP |
| 443 | TCP | HTTPS |
| 3306 | TCP | MySQL |
| 3389 | TCP | RDP |
| 5432 | TCP | PostgreSQL |
| 8080 | TCP | HTTP-Alt |

---

## 🤝 Contributing

Contributions are welcome! 

1. Fork repository
2. Create feature branch: `git checkout -b feature/AmazingFeature`
3. Commit changes: `git commit -m 'Add AmazingFeature'`
4. Push to branch: `git push origin feature/AmazingFeature`
5. Open Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Tác giả

**Trinh Duy Hieu**

- GitHub: [@trinhduyhieuVN](https://github.com/trinhduyhieuVN)
- Email: contact@trinhduyhieu.com

---

## 🙏 Acknowledgments

- **Dear ImGui** by Omar Cornut - Amazing immediate-mode GUI framework
- **GLFW** - Multi-platform library for OpenGL
- **Npcap** by Nmap Project - Packet capture library for Windows
- **Wireshark** - Inspiration for UI design

---

## 📞 Support

Nếu gặp vấn đề hoặc có câu hỏi:

1. **Check Issues**: https://github.com/trinhduyhieuVN/PacketCaptureGUI/issues
2. **Open New Issue**: Mô tả chi tiết vấn đề + attach screenshots
3. **Email**: contact@trinhduyhieu.com

---

<div align="center">

**⭐ Star this repository if you find it helpful!**

Made with ❤️ by [Trinh Duy Hieu](https://github.com/trinhduyhieuVN)

</div>
