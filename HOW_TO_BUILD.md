# 🔨 Hướng Dẫn Build PacketCaptureGUI

## ✅ Build Thành Công!

**File executable:** `build\bin\Release\PacketCaptureGUI.exe` (702 KB)

---

## 📋 Yêu Cầu Hệ Thống

### Phần Mềm Cần Thiết:
- ✅ **Windows 10/11** (64-bit)
- ✅ **Visual Studio 2022** (Community hoặc cao hơn)
  - Workload: "Desktop development with C++"
- ✅ **CMake 3.10+**
- ✅ **Npcap SDK** tại `C:\npcap-sdk\`
- ✅ **Npcap Runtime** (đã cài đặt)

### Kiểm Tra Npcap SDK:
```powershell
# Verify Npcap SDK structure
Test-Path "C:\npcap-sdk\Include\pcap.h"
Test-Path "C:\npcap-sdk\Lib\x64\wpcap.lib"
```

Nếu chưa có, download tại: https://npcap.com/dist/npcap-sdk-1.13.zip

---

## 🚀 Cách Build - Phương Pháp 1: PowerShell (Khuyên Dùng)

### Bước 1: Mở PowerShell hoặc Terminal

```powershell
# Di chuyển đến thư mục dự án
cd "D:\Project\Network Programming\PacketCaptureGUI"
```

### Bước 2: Xóa Build Cũ (nếu có)

```powershell
# Xóa thư mục build cũ
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
```

### Bước 3: Tạo Thư Mục Build

```powershell
# Tạo thư mục build mới
mkdir build
cd build
```

### Bước 4: Generate Project với CMake

```powershell
# Generate Visual Studio solution
cmake ..
```

**Kết quả mong đợi:**
```
-- Building for: Visual Studio 17 2022
-- The CXX compiler identification is MSVC 19.44
-- Configuring done
-- Generating done
-- Build files have been written to: .../build
```

### Bước 5: Build Project

```powershell
# Build Release version
cmake --build . --config Release
```

**Kết quả mong đợi:**
```
Building Custom Rule ...
main.cpp
packet_capture.cpp
imgui.cpp
...
PacketCaptureGUI.exe -> .../build/bin/Release/PacketCaptureGUI.exe
Build succeeded.
```

### Bước 6: Verify Build

```powershell
# Kiểm tra file .exe đã được tạo
Test-Path "bin\Release\PacketCaptureGUI.exe"
# Output: True

# Xem thông tin file
Get-Item "bin\Release\PacketCaptureGUI.exe"
```

---

## 🛠️ Cách Build - Phương Pháp 2: Visual Studio GUI

### Bước 1: Generate Solution

```powershell
cd "D:\Project\Network Programming\PacketCaptureGUI"
mkdir build
cd build
cmake ..
```

### Bước 2: Mở Solution

```powershell
# Mở file .sln trong Visual Studio
start PacketCaptureGUI.sln
```

### Bước 3: Build trong Visual Studio

1. Chọn **Release** configuration (góc trên)
2. Menu: **Build → Build Solution** (hoặc `Ctrl+Shift+B`)
3. Chờ build hoàn thành
4. Xem Output window để check progress

### Bước 4: Tìm File Executable

```
build\bin\Release\PacketCaptureGUI.exe
```

---

## ▶️ Chạy Ứng Dụng

### ⚠️ **QUAN TRỌNG: Phải chạy với quyền Administrator!**

### Cách 1: PowerShell

```powershell
# Từ thư mục build
cd bin\Release
Start-Process -FilePath ".\PacketCaptureGUI.exe" -Verb RunAs
```

### Cách 2: File Explorer

1. Mở thư mục: `build\bin\Release\`
2. Right-click vào `PacketCaptureGUI.exe`
3. Chọn **"Run as administrator"**

### Cách 3: Tạo Shortcut với Admin Rights

```powershell
# Tạo shortcut trên Desktop
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\PacketCaptureGUI.lnk")
$Shortcut.TargetPath = "D:\Project\Network Programming\PacketCaptureGUI\build\bin\Release\PacketCaptureGUI.exe"
$Shortcut.Save()

# Sau đó set "Run as administrator" bằng tay:
# Right-click shortcut → Properties → Advanced → Run as administrator
```

---

## 🐛 Xử Lý Lỗi Build

### Lỗi 1: "Cannot find Npcap SDK"

```
Error: FATAL_ERROR "Npcap SDK not found at C:/npcap-sdk/Include"
```

**Giải pháp:**
```powershell
# Kiểm tra đường dẫn
Test-Path "C:\npcap-sdk\Include\pcap.h"

# Nếu False, download và giải nén Npcap SDK vào C:\npcap-sdk\
```

### Lỗi 2: "MSBuild not found"

```
Error: CMAKE_MAKE_PROGRAM is not set
```

**Giải pháp:**
```powershell
# Install Visual Studio 2022 với C++ workload
# Hoặc chỉ định path:
cmake .. -G "Visual Studio 17 2022"
```

### Lỗi 3: "OpenGL32.lib not found"

```
Error: Cannot open opengl32.lib
```

**Giải pháp:**
```powershell
# Install Windows SDK trong Visual Studio Installer
# Components → Windows 10 SDK (10.0.19041.0)
```

### Lỗi 4: Build Warning về localtime/sprintf

```
warning C4996: 'localtime': This function or variable may be unsafe
```

**Giải pháp:** Không cần sửa, đây chỉ là warnings (không phải lỗi). Build vẫn thành công.

---

## 🔄 Rebuild Project

### Clean Build

```powershell
# Xóa toàn bộ và build lại
cd "D:\Project\Network Programming\PacketCaptureGUI"
Remove-Item -Recurse -Force build
mkdir build; cd build
cmake ..
cmake --build . --config Release
```

### Rebuild Only

```powershell
# Rebuild mà không xóa cmake cache
cd build
cmake --build . --config Release --clean-first
```

---

## 📦 Build Output Structure

```
PacketCaptureGUI/
├── build/
│   ├── bin/
│   │   └── Release/
│   │       └── PacketCaptureGUI.exe    ← Executable chính (702 KB)
│   ├── external/
│   │   ├── glfw/
│   │   │   └── src/Release/glfw3.lib
│   │   └── imgui/
│   ├── PacketCaptureGUI.sln            ← Visual Studio solution
│   └── PacketCaptureGUI.vcxproj        ← Project file
└── src/
    ├── main.cpp
    ├── packet_capture.cpp
    └── ... (source files)
```

---

## 🧪 Test Build

### Quick Test

```powershell
cd build\bin\Release

# Test 1: Check file exists
Test-Path "PacketCaptureGUI.exe"  # Should be True

# Test 2: Check dependencies (optional)
dumpbin /dependents PacketCaptureGUI.exe

# Test 3: Run (requires admin)
Start-Process -FilePath ".\PacketCaptureGUI.exe" -Verb RunAs
```

### Nếu Chạy Bình Thường (Không Admin):

❌ Sẽ lỗi: "Failed to open adapter. Run as Administrator!"

✅ Cần chạy với quyền admin để capture packets

---

## 📊 Build Performance

| Configuration | Build Time | File Size | Optimization |
|---------------|------------|-----------|--------------|
| Debug         | ~45s       | ~3.5 MB   | None, có debug symbols |
| Release       | ~60s       | ~702 KB   | /O2, stripped symbols |

**Khuyên dùng Release** cho sử dụng thực tế.

---

## 🔍 Verify Features Built Correctly

Sau khi build, check các features mới:

```
✅ Save/Load .pcap      → Check UI has "START SAVE PCAP" button
✅ Export CSV/JSON      → Check UI has "EXPORT CSV/JSON" buttons
✅ BPF Filter           → Check UI has "BPF FILTER" section
✅ Follow TCP Stream    → Right-click packet → context menu
```

---

## 🎯 Next Steps

1. ✅ **Build thành công** → File tại `build\bin\Release\PacketCaptureGUI.exe`
2. ▶️ **Run as Administrator**
3. 🧪 **Test features:**
   - Start capture
   - Apply BPF filter
   - Save .pcap file
   - Export CSV/JSON
   - Follow TCP stream

---

## 🆘 Support

Nếu gặp vấn đề:

1. Check CMake output cho errors/warnings
2. Verify Npcap SDK cài đúng
3. Rebuild from clean state
4. Check Visual Studio có C++ workload

**Build Commands Đầy Đủ (Copy-Paste):**

```powershell
cd "D:\Project\Network Programming\PacketCaptureGUI"
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
mkdir build; cd build
cmake ..
cmake --build . --config Release
cd bin\Release
Start-Process -FilePath ".\PacketCaptureGUI.exe" -Verb RunAs
```

---

**Build Status: ✅ SUCCESS**  
**Executable: ✅ READY**  
**Features: ✅ ALL IMPLEMENTED**

🎊 Dự án sẵn sàng sử dụng!
