# 🔨 Build & Test Instructions

## Prerequisites

Đảm bảo đã cài đặt:
- Visual Studio 2022 với C++ workload
- CMake 3.10+
- Npcap SDK tại `C:\npcap-sdk\`
- Npcap Runtime (đã cài đặt)

## Build Steps

### Option 1: Using CMake (Recommended)

```powershell
# Navigate to project directory
cd "D:\Project\Network Programming\PacketCaptureGUI"

# Create build directory
mkdir build
cd build

# Generate Visual Studio project
cmake ..

# Build Release version
cmake --build . --config Release

# Executable will be in: build/bin/PacketCaptureGUI.exe
```

### Option 2: Using Visual Studio

```powershell
# Open the generated solution
build/PacketCaptureGUI.sln

# Select Release configuration
# Build → Build Solution (Ctrl+Shift+B)
```

## Running the Application

**IMPORTANT:** Must run as Administrator!

```powershell
# Method 1: From command line
cd build\bin
.\PacketCaptureGUI.exe

# Method 2: Right-click .exe → Run as Administrator
```

## Testing New Features

### 1. Test BPF Filter

```
1. Start capture
2. In BPF Filter input, enter: tcp port 443
3. Click "APPLY BPF FILTER"
4. Browse HTTPS websites
5. Verify only port 443 traffic appears
```

### 2. Test Save .pcap

```
1. Start capture
2. Click "START SAVE PCAP"
3. Let it capture for 30 seconds
4. Click "STOP SAVE PCAP"
5. Check for file: capture_YYYYMMDD_HHMMSS.pcap
```

### 3. Test Load .pcap

```
1. Use .pcap file from previous test
2. Enter filename in "Load File" field
3. Click "LOAD PCAP FILE"
4. Verify packets appear in list
```

### 4. Test Export CSV/JSON

```
1. Capture or load some packets
2. Click "EXPORT CSV"
3. Open packets_YYYYMMDD_HHMMSS.csv in Excel
4. Click "EXPORT JSON"
5. Open packets_YYYYMMDD_HHMMSS.json in text editor
```

### 5. Test Follow TCP Stream

```
1. Visit http://example.com (HTTP, not HTTPS)
2. Right-click any HTTP packet in list
3. Select "Follow TCP Stream"
4. View client/server conversation
5. Switch between tabs
6. Try "Save as Text File"
```

## Troubleshooting

### Build Errors

**Error: "Cannot find Npcap SDK"**
```
Solution: Verify Npcap SDK is at C:\npcap-sdk\
Check CMakeLists.txt line 16-17
```

**Error: "Missing imgui files"**
```
Solution: CMake will auto-download ImGui
Delete build folder and re-run cmake
```

### Runtime Errors

**Error: "Failed to open adapter"**
```
Solution: Run as Administrator
Npcap requires elevated privileges
```

**Error: "No devices found"**
```
Solution: 
1. Reinstall Npcap Runtime
2. Check "WinPcap API-compatible mode" during install
```

**BPF Filter fails**
```
Solution:
1. Check filter syntax (use Wireshark syntax)
2. Start capture first before applying filter
3. Check error message in status bar
```

## Performance Testing

### High Traffic Scenario

```powershell
# Generate high traffic using PowerShell
while ($true) {
    Invoke-WebRequest -Uri "http://example.com" -UseBasicParsing
    Start-Sleep -Milliseconds 100
}
```

Monitor:
- Packet count
- Memory usage (Task Manager)
- UI responsiveness

### Large .pcap File

```
1. Download large .pcap sample from:
   https://wiki.wireshark.org/SampleCaptures
   
2. Load file and check:
   - Load time
   - Memory usage
   - Scroll performance
```

## Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| Slow packet capture | Use BPF filter to reduce traffic |
| High memory usage | Clear buffer regularly, set max packets |
| UI freezes | Check if capture is running in background |
| Can't load .pcap | Verify file is valid libpcap format |
| Export fails | Check disk space and write permissions |

## File Locations

After running:
```
PacketCaptureGUI/
├── build/bin/
│   └── PacketCaptureGUI.exe       ← Executable
├── capture_YYYYMMDD_HHMMSS.pcap   ← Saved captures
├── packets_YYYYMMDD_HHMMSS.csv    ← CSV exports
├── packets_YYYYMMDD_HHMMSS.json   ← JSON exports
└── tcp_stream_YYYYMMDD_HHMMSS.txt ← TCP streams
```

## Debug Mode

To enable debug output:
```cpp
// In main.cpp, check console output
std::cout shows first 5 packets captured
```

Run from PowerShell to see console:
```powershell
.\PacketCaptureGUI.exe
# Console will show debug messages
```

## Next Steps

After verifying all features work:

1. ✅ Test on different network interfaces
2. ✅ Capture various protocols (HTTP, DNS, ICMP)
3. ✅ Export data and verify format
4. ✅ Load exported .pcap files
5. ✅ Follow TCP streams for HTTP traffic
6. ✅ Test BPF filters with complex expressions

## Support

If issues persist:
1. Check CMake output for warnings
2. Verify all dependencies installed
3. Try rebuilding from clean state
4. Check Windows Event Viewer for errors

---

**Build Status: ✅ Ready to Build**
**Test Status: ⏳ Awaiting Testing**
