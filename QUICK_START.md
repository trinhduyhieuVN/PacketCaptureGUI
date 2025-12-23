# 🚀 Quick Start Guide - PacketCaptureGUI

## ⚡ Chạy Nhanh trong 3 Phút

### 1️⃣ Kiểm Tra Yêu Cầu

```powershell
# Check Npcap SDK
Test-Path "C:\npcap-sdk\Include\pcap.h"  # Phải là True

# Check executable đã build
Test-Path "D:\Project\Network Programming\PacketCaptureGUI\build\bin\Release\PacketCaptureGUI.exe"
```

✅ **Nếu cả 2 đều True**, tiếp tục bước 2  
❌ **Nếu False**, xem file `HOW_TO_BUILD.md`

---

### 2️⃣ Chạy Ứng Dụng (RUN AS ADMIN!)

```powershell
cd "D:\Project\Network Programming\PacketCaptureGUI\build\bin\Release"
Start-Process -FilePath ".\PacketCaptureGUI.exe" -Verb RunAs
```

Hoặc:
- Right-click `PacketCaptureGUI.exe` → **Run as administrator**

---

### 3️⃣ Basic Usage

#### 📡 Bắt Gói Tin (Capture Packets)

1. **Chọn Network Interface:**
   - Dropdown ở Control Panel (bên trái)
   - Chọn interface có kết nối mạng (thường là WiFi hoặc Ethernet)

2. **Click "START CAPTURE"** (nút xanh lá)

3. **Xem packets xuất hiện** trong bảng Packet List

4. **Click "STOP CAPTURE"** (nút đỏ) khi muốn dừng

#### 🔍 Lọc Gói Tin (Filter)

**Cách 1: Display Filter (sau khi capture)**
```
IP Address: 192.168.1.1
Protocol: TCP
→ Chỉ hiển thị packets match điều kiện
```

**Cách 2: BPF Filter (trước khi capture)**
```
1. Start capture
2. Nhập filter: "tcp port 80"
3. Click "APPLY BPF FILTER"
→ Chỉ capture packets match BPF expression
```

#### 💾 Lưu & Xuất Dữ Liệu

**Save to .pcap:**
```
1. Start capture
2. Click "START SAVE PCAP"
→ File: capture_YYYYMMDD_HHMMSS.pcap
```

**Export to CSV/JSON:**
```
1. Capture một số packets
2. Click "EXPORT CSV" hoặc "EXPORT JSON"
→ Files: packets_YYYYMMDD_HHMMSS.csv/json
```

**Load .pcap file:**
```
1. Nhập tên file: "capture.pcap"
2. Click "LOAD PCAP FILE"
→ All packets loaded vào buffer
```

#### 🔄 Theo Dõi TCP Stream

```
1. Capture HTTP traffic (browse http://example.com)
2. Right-click vào TCP packet trong list
3. Chọn "Follow TCP Stream"
4. Xem conversation trong popup window
5. Switch tabs: Client→Server / Server→Client
6. Click "Save as Text File" để export
```

---

## 📚 Ví Dụ Thực Tế

### Example 1: Capture HTTP Traffic

```
1. Start capture
2. BPF Filter: "tcp port 80"
3. Apply filter
4. Browse: http://example.com
5. See HTTP GET request và response
6. Right-click packet → Follow TCP Stream
7. View full HTTP conversation
```

### Example 2: Analyze DNS Queries

```
1. Start capture
2. BPF Filter: "udp port 53"
3. Apply filter
4. Browse any website
5. See DNS query packets (Protocol: DNS)
6. Click packet to see details:
   - Query name (e.g., www.google.com)
   - Response IPs
```

### Example 3: Monitor ICMP (Ping)

```
1. Start capture
2. BPF Filter: "icmp"
3. Open PowerShell, run: ping 8.8.8.8
4. See Echo Request và Echo Reply packets
5. Check sequence numbers, timestamps
```

### Example 4: Save Session for Later Analysis

```
1. Start capture (no filter)
2. Click "START SAVE PCAP"
3. Browse websites, download files, etc.
4. After 5 minutes, click "STOP SAVE PCAP"
5. Later: Load .pcap file để replay và analyze
```

---

## 🎯 BPF Filter Examples

```
# Capture chỉ HTTP
tcp port 80

# Capture HTTPS
tcp port 443

# Capture HTTP or HTTPS
tcp port 80 or tcp port 443

# Capture traffic từ/đến specific IP
host 192.168.1.100

# Capture traffic giữa 2 IPs
host 192.168.1.1 and host 8.8.8.8

# Capture TCP traffic trên subnet
net 192.168.1.0/24 and tcp

# Loại trừ ICMP
not icmp

# Chỉ DNS queries
udp port 53

# Chỉ TCP SYN packets
tcp[tcpflags] & tcp-syn != 0

# Packets lớn hơn 1000 bytes
greater 1000
```

---

## 🖱️ UI Controls Cheat Sheet

### Control Panel (Left Side)

| Control | Action |
|---------|--------|
| **Interface Dropdown** | Chọn network adapter |
| **IP Filter** | Filter by IP address |
| **Protocol Filter** | Filter by protocol name |
| **START CAPTURE** | Bắt đầu capture (GREEN) |
| **STOP CAPTURE** | Dừng capture (RED) |
| **CLEAR ALL** | Xóa tất cả packets |
| **EXPORT CSV** | Export to CSV file |
| **EXPORT JSON** | Export to JSON file |
| **BPF Filter Input** | Nhập BPF expression |
| **APPLY BPF FILTER** | Áp dụng BPF filter |
| **START SAVE PCAP** | Bắt đầu save to .pcap |
| **STOP SAVE PCAP** | Dừng save .pcap |
| **Load File Input** | Tên file .pcap to load |
| **LOAD PCAP FILE** | Load existing .pcap |

### Packet List (Center)

| Action | Result |
|--------|--------|
| **Click packet** | Xem details ở panel dưới |
| **Right-click TCP packet** | Context menu → Follow TCP Stream |
| **Scroll** | Auto-scroll nếu enabled |

### Packet Details (Bottom)

| Tab | Content |
|-----|---------|
| **Protocol Tree** | Chi tiết từng layer |
| **Hex Dump** | Raw data in hex + ASCII |

### TCP Stream Window

| Tab | Content |
|-----|---------|
| **Client → Server** | Data sent by client |
| **Server → Client** | Data sent by server |
| **Export** | Save stream to file |

---

## ⌨️ Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Ctrl+Shift+B` | Build project (trong VS) |
| `Esc` | Close popup windows |
| `Mouse Wheel` | Scroll packet list |
| `Click` | Select packet |
| `Right Click` | Context menu |

---

## 🔧 Troubleshooting

### "Failed to open adapter"
→ **Run as Administrator!**

### Không thấy packets
→ Check interface đã chọn đúng?  
→ Có traffic trên interface không?

### BPF Filter error
→ Check syntax (dùng Wireshark syntax)  
→ Start capture trước khi apply filter

### Export fails
→ Check disk space  
→ Check write permissions

### TCP Stream empty
→ Ensure packet có data payload  
→ Try với HTTP traffic (port 80)

---

## 📁 Output Files Location

Tất cả files được save trong thư mục hiện tại của executable:

```
PacketCaptureGUI/build/bin/Release/
├── PacketCaptureGUI.exe
├── capture_20251223_153045.pcap      ← Saved captures
├── packets_20251223_153100.csv        ← CSV exports
├── packets_20251223_153105.json       ← JSON exports
└── tcp_stream_20251223_153110.txt     ← TCP streams
```

---

## 🎓 Pro Tips

### 1. Giảm Packet Overload
```
→ Dùng BPF filter để capture chỉ traffic cần thiết
→ Click "CLEAR ALL" thường xuyên
→ Set max packets trong code (default: 1000)
```

### 2. Analyze Specific Connection
```
→ Capture all
→ Identify connection bằng IP:Port
→ Apply display filter
→ Follow TCP stream
```

### 3. Share Analysis với Team
```
→ Save to .pcap
→ Gửi file cho team
→ Team có thể mở bằng Wireshark hoặc app này
```

### 4. Debug Network Issues
```
→ Capture khi issue xảy ra
→ Export to CSV
→ Analyze trong Excel (sort, filter, pivot)
```

---

## 📖 Learn More

- **Full Documentation:** `README.md`
- **Build Guide:** `HOW_TO_BUILD.md`
- **Implementation Details:** `IMPLEMENTATION_COMPLETE.md`
- **Testing Guide:** `BUILD_AND_TEST.md`

---

## ✅ Quick Checklist

Before using:
- [ ] Npcap Runtime installed
- [ ] Run as Administrator
- [ ] Network interface connected
- [ ] Know what traffic to capture

During capture:
- [ ] Selected correct interface
- [ ] Applied BPF filter (if needed)
- [ ] Monitoring packet count
- [ ] Saving to .pcap (if needed)

After capture:
- [ ] Reviewed packets
- [ ] Filtered relevant data
- [ ] Followed TCP streams
- [ ] Exported analysis

---

**🎉 Bạn đã sẵn sàng bắt đầu analyze network traffic!**

**First Capture:**
```powershell
# Run app
Start-Process -FilePath ".\PacketCaptureGUI.exe" -Verb RunAs

# In app:
1. Select interface
2. START CAPTURE
3. Browse web
4. STOP CAPTURE
5. Click packets to explore
```

Happy Packet Hunting! 🦈
