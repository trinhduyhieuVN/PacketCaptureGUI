/*
 * Network Packet Analyzer - Modern Professional GUI
 * Wireshark-style interface with Dear ImGui
 * Full-featured packet capture and analysis
 */

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "packet_capture.h"
#include "packet_data.h"
#include "packet_exporter.h"
#include "tcp_stream.h"

#include <GLFW/glfw3.h>
#define GLFW_EXPOSE_NATIVE_WIN32
#include <GLFW/glfw3native.h>
#include <windows.h>
#include <commdlg.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <ctime>

// ============== Global State ==============
static GLFWwindow* g_Window = nullptr;
static PacketBuffer g_PacketBuffer;
static PacketCapture g_Capture;
static TCPStreamTracker g_StreamTracker;
static int g_SelectedDevice = -1;  // -1 = auto-select best adapter
static int g_SelectedPacket = -1;
static char g_FilterIP[128] = "";
static char g_FilterProtocol[64] = "";
static char g_BPFFilter[256] = "";
static bool g_AutoScroll = true;
static bool g_DarkTheme = true;
static bool g_ShowStreamWindow = false;
static TCPStream g_SelectedStream;
static bool g_FirstRun = true;

// Capture statistics
static std::chrono::steady_clock::time_point g_CaptureStartTime;
static uint64_t g_TotalBytes = 0;

// Protocol stats
static int g_TCPCount = 0;
static int g_UDPCount = 0;
static int g_ICMPCount = 0;
static int g_ARPCount = 0;
static int g_OtherCount = 0;

// Status messages
static std::string g_StatusMessage = "Ready - Select interface and click Start";
static bool g_StatusIsError = false;

// ============== File Dialog Helpers ==============
static std::string openSaveFileDialog(GLFWwindow* window, const char* filter, const char* defaultExt, const char* defaultName = nullptr) {
    OPENFILENAME ofn;
    char szFile[260] = {0};
    
    if (defaultName) {
        strcpy_s(szFile, sizeof(szFile), defaultName);
    }
    
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = glfwGetWin32Window(window);
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = filter;
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.lpstrDefExt = defaultExt;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
    
    if (GetSaveFileName(&ofn) == TRUE) {
        return std::string(ofn.lpstrFile);
    }
    return "";
}

static std::string openLoadFileDialog(GLFWwindow* window, const char* filter) {
    OPENFILENAME ofn;
    char szFile[260] = {0};
    
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = glfwGetWin32Window(window);
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = filter;
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    
    if (GetOpenFileName(&ofn) == TRUE) {
        return std::string(ofn.lpstrFile);
    }
    return "";
}

void onPacketReceived(const PacketInfo& packet) {
    // Debug: Print to console to verify callback is working
    static int debug_count = 0;
    if (debug_count < 5) {
        std::cout << "Packet #" << packet.id << " captured: " << packet.protocol 
                  << " " << packet.src_ip << " -> " << packet.dst_ip << std::endl;
        debug_count++;
    }
    
    g_PacketBuffer.addPacket(packet);
    g_TotalBytes += packet.length;
    
    // Track TCP streams
    if (packet.has_tcp) {
        g_StreamTracker.addPacket(packet);
    }
    
    if (packet.protocol == "TCP") g_TCPCount++;
    else if (packet.protocol == "UDP") g_UDPCount++;
    else if (packet.protocol == "ICMP") g_ICMPCount++;
    else if (packet.protocol == "ARP") g_ARPCount++;
    else g_OtherCount++;
}

void resetStatistics() {
    g_TotalBytes = 0;
    g_TCPCount = g_UDPCount = g_ICMPCount = g_ARPCount = g_OtherCount = 0;
    g_StreamTracker.clear();
}

void setupDarkTheme() {
    ImGuiStyle& style = ImGui::GetStyle();
    ImVec4* colors = style.Colors;
    
    colors[ImGuiCol_WindowBg] = ImVec4(0.10f, 0.10f, 0.12f, 1.00f);
    colors[ImGuiCol_ChildBg] = ImVec4(0.12f, 0.12f, 0.14f, 1.00f);
    colors[ImGuiCol_Border] = ImVec4(0.30f, 0.30f, 0.35f, 1.00f);
    colors[ImGuiCol_FrameBg] = ImVec4(0.18f, 0.18f, 0.22f, 1.00f);
    colors[ImGuiCol_FrameBgHovered] = ImVec4(0.25f, 0.25f, 0.30f, 1.00f);
    colors[ImGuiCol_TitleBg] = ImVec4(0.08f, 0.08f, 0.10f, 1.00f);
    colors[ImGuiCol_TitleBgActive] = ImVec4(0.12f, 0.12f, 0.15f, 1.00f);
    colors[ImGuiCol_Header] = ImVec4(0.20f, 0.40f, 0.60f, 0.80f);
    colors[ImGuiCol_HeaderHovered] = ImVec4(0.25f, 0.50f, 0.75f, 0.90f);
    colors[ImGuiCol_Button] = ImVec4(0.20f, 0.40f, 0.60f, 1.00f);
    colors[ImGuiCol_ButtonHovered] = ImVec4(0.25f, 0.50f, 0.75f, 1.00f);
    colors[ImGuiCol_TableHeaderBg] = ImVec4(0.15f, 0.15f, 0.18f, 1.00f);
    colors[ImGuiCol_TableRowBgAlt] = ImVec4(1.00f, 1.00f, 1.00f, 0.03f);
    
    style.WindowRounding = 8.0f;
    style.ChildRounding = 6.0f;
    style.FrameRounding = 5.0f;
    style.ScrollbarRounding = 5.0f;
    style.GrabRounding = 5.0f;
    
    style.WindowPadding = ImVec2(20, 20);
    style.FramePadding = ImVec2(14, 10);
    style.ItemSpacing = ImVec2(14, 12);
    style.ScrollbarSize = 20.0f;
    style.GrabMinSize = 16.0f;
    style.WindowBorderSize = 1.0f;
    style.ChildBorderSize = 1.0f;
}

// ============== Helper: Detect Active Adapters ==============
int getAdapterPriority(const std::string& desc) {
    std::string lower = desc;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    // Priority scoring
    if (lower.find("wi-fi") != std::string::npos || 
        lower.find("wifi") != std::string::npos || 
        lower.find("wireless") != std::string::npos) {
        return 100;  // WiFi highest priority
    }
    if (lower.find("ethernet") != std::string::npos || 
        lower.find("realtek") != std::string::npos ||
        lower.find("intel") != std::string::npos) {
        return 90;   // Ethernet second
    }
    if (lower.find("loopback") != std::string::npos) {
        return 10;   // Loopback low priority
    }
    if (lower.find("bluetooth") != std::string::npos) {
        return 20;
    }
    if (lower.find("virtual") != std::string::npos || 
        lower.find("miniport") != std::string::npos) {
        return 5;    // Virtual adapters lowest
    }
    return 50;  // Unknown
}

std::string getAdapterIcon(const std::string& desc) {
    std::string lower = desc;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    if (lower.find("wi-fi") != std::string::npos || 
        lower.find("wifi") != std::string::npos || 
        lower.find("wireless") != std::string::npos) {
        return "[WiFi] ";
    }
    if (lower.find("ethernet") != std::string::npos) {
        return "[ETH] ";
    }
    if (lower.find("bluetooth") != std::string::npos) {
        return "[BT] ";
    }
    if (lower.find("loopback") != std::string::npos) {
        return "[LOOP] ";
    }
    if (lower.find("virtual") != std::string::npos) {
        return "[VIRT] ";
    }
    return "";
}

// ============== Title Bar ==============
void renderTitleBar() {
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->Pos);
    ImGui::SetNextWindowSize(ImVec2(viewport->Size.x, 70));
    
    ImGui::Begin("##TitleBar", nullptr, 
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | 
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoBringToFrontOnFocus);
    
    ImGui::SetCursorPosY(18);
    ImGui::SetCursorPosX(30);
    ImGui::TextColored(ImVec4(0.3f, 0.75f, 1.0f, 1.0f), "NETWORK PACKET ANALYZER");
    
    ImGui::SameLine(viewport->Size.x - 350);
    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), "Professional Network Monitor");
    
    ImGui::SameLine(viewport->Size.x - 100);
    if (ImGui::Button(g_DarkTheme ? "Light" : "Dark", ImVec2(80, 35))) {
        g_DarkTheme = !g_DarkTheme;
        if (g_DarkTheme) setupDarkTheme();
        else ImGui::StyleColorsLight();
    }
    
    ImGui::End();
}

// ============== Control Panel ==============
void renderControlPanel() {
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2(viewport->Pos.x, viewport->Pos.y + 70));
    ImGui::SetNextWindowSize(ImVec2(380, viewport->Size.y - 130));
    
    ImGui::Begin("Capture Control", nullptr, 
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse);
    
    auto devices = PacketCapture::getDevices();
    
    // Auto-select best adapter on first run
    if (g_FirstRun && !devices.empty()) {
        int best_idx = 0;
        int best_priority = 0;
        
        for (int i = 0; i < (int)devices.size(); i++) {
            int priority = getAdapterPriority(devices[i].second);
            if (priority > best_priority) {
                best_priority = priority;
                best_idx = i;
            }
        }
        
        g_SelectedDevice = best_idx;
        g_FirstRun = false;
        
        // Log auto-selection
        std::cout << "Auto-selected adapter #" << best_idx << ": " 
                  << devices[best_idx].second << std::endl;
    }
    
    // Ensure valid selection
    if (g_SelectedDevice < 0 || g_SelectedDevice >= (int)devices.size()) {
        g_SelectedDevice = devices.empty() ? -1 : 0;
    }
    
    // ===== Interface Selection =====
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.85f, 1.0f, 1.0f));
    ImGui::Text("NETWORK INTERFACE");
    ImGui::PopStyleColor();
    ImGui::Separator();
    ImGui::Spacing();
    
    // Display current selection
    std::string current_label = "Select interface...";
    if (g_SelectedDevice >= 0 && g_SelectedDevice < (int)devices.size()) {
        current_label = getAdapterIcon(devices[g_SelectedDevice].second) + 
                       devices[g_SelectedDevice].second;
    }
    
    ImGui::SetNextItemWidth(-1);
    if (ImGui::BeginCombo("##Interface", current_label.c_str())) {
        for (int i = 0; i < (int)devices.size(); i++) {
            bool is_selected = (g_SelectedDevice == i);
            
            // Build label with icon and priority indicator
            std::string icon = getAdapterIcon(devices[i].second);
            int priority = getAdapterPriority(devices[i].second);
            
            // Color based on priority
            ImVec4 color;
            if (priority >= 90) {
                color = ImVec4(0.4f, 1.0f, 0.5f, 1.0f);  // Green for WiFi/Ethernet
            } else if (priority >= 50) {
                color = ImVec4(1.0f, 1.0f, 0.6f, 1.0f);  // Yellow for others
            } else {
                color = ImVec4(0.6f, 0.6f, 0.6f, 1.0f);  // Gray for virtual
            }
            
            ImGui::PushStyleColor(ImGuiCol_Text, color);
            
            std::string label = std::to_string(i+1) + ". " + icon + devices[i].second;
            
            if (ImGui::Selectable(label.c_str(), is_selected)) {
                g_SelectedDevice = i;
            }
            
            ImGui::PopStyleColor();
            
            if (is_selected) {
                ImGui::SetItemDefaultFocus();
            }
        }
        ImGui::EndCombo();
    }
    
    // Show adapter info
    if (g_SelectedDevice >= 0 && g_SelectedDevice < (int)devices.size()) {
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Type: %s", 
            getAdapterIcon(devices[g_SelectedDevice].second).c_str());
    }
    
    ImGui::Spacing();
    ImGui::Spacing();
    
    // ===== Filters =====
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.85f, 1.0f, 1.0f));
    ImGui::Text("CAPTURE FILTER");
    ImGui::PopStyleColor();
    ImGui::Separator();
    ImGui::Spacing();
    
    ImGui::Text("IP Address:");
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##FilterIP", "e.g. 192.168.1.1", g_FilterIP, sizeof(g_FilterIP));
    
    ImGui::Text("Protocol:");
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##FilterProto", "e.g. TCP, UDP, ICMP", g_FilterProtocol, sizeof(g_FilterProtocol));
    
    ImGui::Spacing();
    ImGui::Spacing();
    
    // ===== Control Buttons =====
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.85f, 1.0f, 1.0f));
    ImGui::Text("CAPTURE CONTROL");
    ImGui::PopStyleColor();
    ImGui::Separator();
    ImGui::Spacing();
    
    // Start Button - GREEN
    if (!g_Capture.isRunning()) {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.15f, 0.65f, 0.25f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.2f, 0.75f, 0.3f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.15f, 0.85f, 0.35f, 1.0f));
        
        if (ImGui::Button("START CAPTURE", ImVec2(-1, 60))) {
            if (g_SelectedDevice < (int)devices.size()) {
                resetStatistics();
                g_CaptureStartTime = std::chrono::steady_clock::now();
                
                // Debug output
                std::cout << "\n=== Starting capture ===" << std::endl;
                std::cout << "Selected device index: " << g_SelectedDevice << std::endl;
                std::cout << "Device name: " << devices[g_SelectedDevice].first << std::endl;
                std::cout << "Device desc: " << devices[g_SelectedDevice].second << std::endl;
                std::cout << "Total devices available: " << devices.size() << std::endl;
                
                if (g_Capture.start(devices[g_SelectedDevice].first, onPacketReceived)) {
                    g_StatusMessage = "Capturing on " + devices[g_SelectedDevice].second;
                    g_StatusIsError = false;
                    std::cout << "Capture started successfully!" << std::endl;
                    std::cout << "Waiting for packets..." << std::endl;
                } else {
                    g_StatusMessage = "ERROR: Failed to open adapter. Run as Administrator!";
                    g_StatusIsError = true;
                    std::cerr << "ERROR: Failed to start capture!" << std::endl;
                }
            } else {
                g_StatusMessage = "ERROR: Please select a network interface first";
                g_StatusIsError = true;
                std::cerr << "ERROR: No device selected (index=" << g_SelectedDevice 
                         << ", available=" << devices.size() << ")" << std::endl;
            }
        }
        ImGui::PopStyleColor(3);
    } 
    // Stop Button - RED
    else {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.75f, 0.18f, 0.18f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.85f, 0.25f, 0.25f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.95f, 0.3f, 0.3f, 1.0f));
        
        if (ImGui::Button("STOP CAPTURE", ImVec2(-1, 60))) {
            g_Capture.stop();
            g_StatusMessage = "Capture stopped";
            g_StatusIsError = false;
        }
        ImGui::PopStyleColor(3);
    }
    
    ImGui::Spacing();
    
    // Clear Button - GRAY
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.45f, 0.45f, 0.5f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.55f, 0.55f, 0.6f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.6f, 0.6f, 0.65f, 1.0f));
    
    if (ImGui::Button("CLEAR ALL", ImVec2(-1, 50))) {
        g_PacketBuffer.clear();
        g_SelectedPacket = -1;
        resetStatistics();
        g_StatusMessage = "All packets cleared";
        g_StatusIsError = false;
    }
    ImGui::PopStyleColor(3);
    
    ImGui::Spacing();
    
    // ===== Export Section =====
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.85f, 1.0f, 1.0f));
    ImGui::Text("EXPORT DATA");
    ImGui::PopStyleColor();
    ImGui::Separator();
    ImGui::Spacing();
    
    // Export CSV Button - BLUE
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2f, 0.5f, 0.8f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.3f, 0.6f, 0.9f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.4f, 0.7f, 1.0f, 1.0f));
    
    if (ImGui::Button("EXPORT CSV", ImVec2(-1, 45))) {
        auto packets = g_PacketBuffer.getPackets();
        if (packets.empty()) {
            g_StatusMessage = "ERROR: No packets to export";
            g_StatusIsError = true;
        } else {
            // Generate default filename
            auto now = std::chrono::system_clock::now();
            auto time = std::chrono::system_clock::to_time_t(now);
            struct tm timeinfo;
            localtime_s(&timeinfo, &time);
            char defaultName[100];
            sprintf_s(defaultName, sizeof(defaultName), "packets_%04d%02d%02d_%02d%02d%02d.csv",
                     timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
                     timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
            
            std::string filename = openSaveFileDialog(g_Window, 
                "CSV Files (*.csv)\0*.csv\0All Files (*.*)\0*.*\0", 
                "csv", defaultName);
            
            if (!filename.empty()) {
                if (PacketExporter::exportToCSV(packets, filename)) {
                    g_StatusMessage = "Exported to " + filename;
                    g_StatusIsError = false;
                } else {
                    g_StatusMessage = "ERROR: Failed to export CSV";
                    g_StatusIsError = true;
                }
            }
        }
    }
    ImGui::PopStyleColor(3);
    
    ImGui::Spacing();
    
    // Export JSON Button - GREEN
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2f, 0.7f, 0.4f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.3f, 0.8f, 0.5f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.4f, 0.9f, 0.6f, 1.0f));
    
    if (ImGui::Button("EXPORT JSON", ImVec2(-1, 45))) {
        auto packets = g_PacketBuffer.getPackets();
        if (packets.empty()) {
            g_StatusMessage = "ERROR: No packets to export";
            g_StatusIsError = true;
        } else {
            // Generate default filename
            auto now = std::chrono::system_clock::now();
            auto time = std::chrono::system_clock::to_time_t(now);
            struct tm timeinfo;
            localtime_s(&timeinfo, &time);
            char defaultName[100];
            sprintf_s(defaultName, sizeof(defaultName), "packets_%04d%02d%02d_%02d%02d%02d.json",
                     timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
                     timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
            
            std::string filename = openSaveFileDialog(g_Window, 
                "JSON Files (*.json)\0*.json\0All Files (*.*)\0*.*\0", 
                "json", defaultName);
            
            if (!filename.empty()) {
                if (PacketExporter::exportToJSON(packets, filename)) {
                    g_StatusMessage = "Exported to " + filename;
                    g_StatusIsError = false;
                } else {
                    g_StatusMessage = "ERROR: Failed to export JSON";
                    g_StatusIsError = true;
                }
            }
        }
    }
    ImGui::PopStyleColor(3);
    
    ImGui::Spacing();
    ImGui::Spacing();
    
    // ===== BPF Filter Section =====
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.85f, 1.0f, 1.0f));
    ImGui::Text("BPF FILTER");
    ImGui::PopStyleColor();
    ImGui::Separator();
    ImGui::Spacing();
    
    ImGui::Text("Filter Expression:");
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##BPFFilter", "e.g. tcp port 80", g_BPFFilter, sizeof(g_BPFFilter));
    
    if (ImGui::Button("APPLY BPF FILTER", ImVec2(-1, 40))) {
        if (g_Capture.isRunning()) {
            if (g_Capture.setBPFFilter(g_BPFFilter)) {
                // Clear old packets to show only filtered packets
                g_PacketBuffer.clear();
                g_StatusMessage = "BPF filter applied (buffer cleared): " + std::string(g_BPFFilter);
                g_StatusIsError = false;
            } else {
                g_StatusMessage = "ERROR: " + g_Capture.getLastError();
                g_StatusIsError = true;
            }
        } else {
            g_StatusMessage = "ERROR: Start capture first";
            g_StatusIsError = true;
        }
    }
    
    ImGui::Spacing();
    ImGui::Spacing();
    
    // ===== Save/Load PCAP Section =====
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.85f, 1.0f, 1.0f));
    ImGui::Text("PCAP FILE");
    ImGui::PopStyleColor();
    ImGui::Separator();
    ImGui::Spacing();
    
    // Save PCAP Button
    if (!g_Capture.isSavingPcap()) {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.6f, 0.4f, 0.8f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.7f, 0.5f, 0.9f, 1.0f));
        
        if (ImGui::Button("START SAVE PCAP", ImVec2(-1, 40))) {
            if (g_Capture.isRunning()) {
                auto now = std::chrono::system_clock::now();
                auto time = std::chrono::system_clock::to_time_t(now);
                struct tm timeinfo;
                localtime_s(&timeinfo, &time);
                char defaultName[100];
                sprintf_s(defaultName, sizeof(defaultName), "capture_%04d%02d%02d_%02d%02d%02d.pcap",
                         timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
                         timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
                
                std::string filename = openSaveFileDialog(g_Window,
                    "PCAP Files (*.pcap)\0*.pcap\0All Files (*.*)\0*.*\0",
                    "pcap", defaultName);
                
                if (!filename.empty()) {
                    if (g_Capture.startSavingPcap(filename)) {
                        g_StatusMessage = "Saving to " + filename;
                        g_StatusIsError = false;
                    } else {
                        g_StatusMessage = "ERROR: " + g_Capture.getLastError();
                        g_StatusIsError = true;
                    }
                }
            } else {
                g_StatusMessage = "ERROR: Start capture first";
                g_StatusIsError = true;
            }
        }
        ImGui::PopStyleColor(2);
    } else {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.4f, 0.4f, 1.0f));
        
        if (ImGui::Button("STOP SAVE PCAP", ImVec2(-1, 40))) {
            g_Capture.stopSavingPcap();
            g_StatusMessage = "Stopped saving PCAP";
            g_StatusIsError = false;
        }
        ImGui::PopStyleColor();
    }
    
    ImGui::Spacing();
    
    // Load PCAP Button
    if (ImGui::Button("LOAD PCAP FILE", ImVec2(-1, 40))) {
        std::string filename = openLoadFileDialog(g_Window,
            "PCAP Files (*.pcap)\0*.pcap\0All Files (*.*)\0*.*\0");
        
        if (!filename.empty()) {
            g_PacketBuffer.clear();
            g_StreamTracker.clear();
            resetStatistics();
            
            if (g_Capture.loadPcapFile(filename, onPacketReceived)) {
                g_StatusMessage = "Loaded " + std::to_string(g_PacketBuffer.size()) + " packets from " + filename;
                g_StatusIsError = false;
            } else {
                g_StatusMessage = "ERROR: " + g_Capture.getLastError();
                g_StatusIsError = true;
            }
        }
    }
    
    ImGui::Spacing();
    ImGui::Spacing();
    
    // ===== Capture Status =====
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.85f, 1.0f, 1.0f));
    ImGui::Text("CAPTURE STATUS");
    ImGui::PopStyleColor();
    ImGui::Separator();
    ImGui::Spacing();
    
    // Status indicator with icon
    if (g_Capture.isRunning()) {
        ImGui::TextColored(ImVec4(0.2f, 0.95f, 0.35f, 1.0f), ">>> CAPTURING <<<");
    } else {
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "    STOPPED");
    }
    
    ImGui::Spacing();
    ImGui::Text("Total Packets: %zu", g_PacketBuffer.size());
    
    // Bytes with unit conversion
    std::string bytesStr;
    if (g_TotalBytes < 1024) bytesStr = std::to_string(g_TotalBytes) + " B";
    else if (g_TotalBytes < 1048576) bytesStr = std::to_string(g_TotalBytes/1024) + " KB";
    else bytesStr = std::to_string(g_TotalBytes/1048576) + " MB";
    ImGui::Text("Total Bytes: %s", bytesStr.c_str());
    
    // Duration timer
    if (g_Capture.isRunning()) {
        auto now = std::chrono::steady_clock::now();
        auto dur = std::chrono::duration_cast<std::chrono::seconds>(now - g_CaptureStartTime).count();
        ImGui::Text("Duration: %02lld:%02lld:%02lld", dur/3600, (dur%3600)/60, dur%60);
    } else {
        ImGui::Text("Duration: --:--:--");
    }
    
    ImGui::Spacing();
    ImGui::Spacing();
    
    // ===== Protocol Statistics =====
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.85f, 1.0f, 1.0f));
    ImGui::Text("PROTOCOL DISTRIBUTION");
    ImGui::PopStyleColor();
    ImGui::Separator();
    ImGui::Spacing();
    
    int total = g_TCPCount + g_UDPCount + g_ICMPCount + g_ARPCount + g_OtherCount;
    if (total > 0) {
        // TCP - Blue
        float tcpPct = (float)g_TCPCount / total;
        ImGui::TextColored(ImVec4(0.4f, 0.7f, 1.0f, 1.0f), "TCP:  %d (%.1f%%)", g_TCPCount, tcpPct*100);
        ImGui::PushStyleColor(ImGuiCol_PlotHistogram, ImVec4(0.4f, 0.7f, 1.0f, 1.0f));
        ImGui::ProgressBar(tcpPct, ImVec2(-1, 16), "");
        ImGui::PopStyleColor();
        
        // UDP - Green
        float udpPct = (float)g_UDPCount / total;
        ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.6f, 1.0f), "UDP:  %d (%.1f%%)", g_UDPCount, udpPct*100);
        ImGui::PushStyleColor(ImGuiCol_PlotHistogram, ImVec4(0.4f, 1.0f, 0.6f, 1.0f));
        ImGui::ProgressBar(udpPct, ImVec2(-1, 16), "");
        ImGui::PopStyleColor();
        
        // ICMP - Yellow
        float icmpPct = (float)g_ICMPCount / total;
        ImGui::TextColored(ImVec4(1.0f, 0.9f, 0.4f, 1.0f), "ICMP: %d (%.1f%%)", g_ICMPCount, icmpPct*100);
        ImGui::PushStyleColor(ImGuiCol_PlotHistogram, ImVec4(1.0f, 0.9f, 0.4f, 1.0f));
        ImGui::ProgressBar(icmpPct, ImVec2(-1, 16), "");
        ImGui::PopStyleColor();
        
        // ARP - Pink
        float arpPct = (float)g_ARPCount / total;
        ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.85f, 1.0f), "ARP:  %d (%.1f%%)", g_ARPCount, arpPct*100);
        ImGui::PushStyleColor(ImGuiCol_PlotHistogram, ImVec4(1.0f, 0.6f, 0.85f, 1.0f));
        ImGui::ProgressBar(arpPct, ImVec2(-1, 16), "");
        ImGui::PopStyleColor();
    } else {
        ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), "No packets captured yet");
    }
    
    ImGui::Spacing();
    ImGui::Spacing();
    
    // ===== Options =====
    ImGui::Checkbox("Auto-scroll packet list", &g_AutoScroll);
    
    ImGui::End();
}

// ============== Packet List Table ==============
void renderPacketList() {
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    float detailsHeight = (g_SelectedPacket >= 0) ? 380 : 0;
    
    ImGui::SetNextWindowPos(ImVec2(viewport->Pos.x + 380, viewport->Pos.y + 70));
    ImGui::SetNextWindowSize(ImVec2(viewport->Size.x - 380, viewport->Size.y - 130 - detailsHeight));
    
    ImGui::Begin("Packet List", nullptr, 
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse);
    
    auto packets = g_PacketBuffer.getPackets();
    
    // Apply filters
    std::vector<PacketInfo> filtered;
    for (const auto& pkt : packets) {
        bool match = true;
        
        if (strlen(g_FilterIP) > 0) {
            std::string f(g_FilterIP);
            if (pkt.src_ip.find(f) == std::string::npos && 
                pkt.dst_ip.find(f) == std::string::npos) {
                match = false;
            }
        }
        
        if (strlen(g_FilterProtocol) > 0) {
            std::string f(g_FilterProtocol);
            std::string p = pkt.protocol;
            std::transform(f.begin(), f.end(), f.begin(), ::toupper);
            std::transform(p.begin(), p.end(), p.begin(), ::toupper);
            if (p.find(f) == std::string::npos) match = false;
        }
        
        if (match) filtered.push_back(pkt);
    }
    
    // Header
    ImGui::Text("Showing %zu of %zu packets", filtered.size(), packets.size());
    if (strlen(g_FilterIP) > 0 || strlen(g_FilterProtocol) > 0) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), " (filtered)");
    }
    ImGui::Separator();
    
    // Packet table
    if (ImGui::BeginTable("##PacketTable", 8, 
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_Resizable | ImGuiTableFlags_Sortable | ImGuiTableFlags_Hideable |
        ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_HighlightHoveredColumn)) {
        
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("No.",         ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Time",        ImGuiTableColumnFlags_WidthFixed, 110.0f);
        ImGui::TableSetupColumn("Source",      ImGuiTableColumnFlags_WidthFixed, 170.0f);
        ImGui::TableSetupColumn("Destination", ImGuiTableColumnFlags_WidthFixed, 170.0f);
        ImGui::TableSetupColumn("Protocol",    ImGuiTableColumnFlags_WidthFixed, 110.0f);
        ImGui::TableSetupColumn("Ports",       ImGuiTableColumnFlags_WidthFixed, 150.0f);
        ImGui::TableSetupColumn("Length",      ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Info",        ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        
        ImGuiListClipper clipper;
        clipper.Begin((int)filtered.size());
        
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; row++) {
                const auto& pkt = filtered[row];
                
                ImGui::TableNextRow(ImGuiTableRowFlags_None, 36.0f);
                
                // Protocol-based row coloring
                ImVec4 textColor = ImVec4(0.9f, 0.9f, 0.9f, 1.0f);
                if (pkt.protocol == "TCP") textColor = ImVec4(0.7f, 0.85f, 1.0f, 1.0f);
                else if (pkt.protocol == "UDP") textColor = ImVec4(0.7f, 1.0f, 0.8f, 1.0f);
                else if (pkt.protocol == "ICMP") textColor = ImVec4(1.0f, 0.95f, 0.7f, 1.0f);
                else if (pkt.protocol == "ARP") textColor = ImVec4(1.0f, 0.8f, 0.9f, 1.0f);
                
                ImGui::PushStyleColor(ImGuiCol_Text, textColor);
                
                // No.
                ImGui::TableSetColumnIndex(0);
                bool is_selected = (g_SelectedPacket == pkt.id);
                if (ImGui::Selectable(std::to_string(pkt.id).c_str(), is_selected,
                    ImGuiSelectableFlags_SpanAllColumns)) {
                    g_SelectedPacket = pkt.id;
                }
                
                // Context menu for TCP packets
                if (ImGui::BeginPopupContextItem()) {
                    if (pkt.has_tcp && ImGui::MenuItem("Follow TCP Stream")) {
                        TCPStream* stream = g_StreamTracker.findStream(pkt);
                        if (stream) {
                            g_SelectedStream = *stream;
                            g_SelectedStream.reassemble();
                            g_ShowStreamWindow = true;
                        }
                    }
                    ImGui::EndPopup();
                }
                
                // Time
                ImGui::TableSetColumnIndex(1);
                time_t t = (time_t)pkt.timestamp;
                struct tm* tm_info = localtime(&t);
                char timeBuf[16];
                strftime(timeBuf, sizeof(timeBuf), "%H:%M:%S", tm_info);
                ImGui::Text("%s", timeBuf);
                
                // Source
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%s", pkt.src_ip.empty() ? pkt.src_mac.c_str() : pkt.src_ip.c_str());
                
                // Destination
                ImGui::TableSetColumnIndex(3);
                ImGui::Text("%s", pkt.dst_ip.empty() ? pkt.dst_mac.c_str() : pkt.dst_ip.c_str());
                
                // Protocol
                ImGui::TableSetColumnIndex(4);
                ImGui::Text("%s", pkt.protocol.c_str());
                
                // Ports
                ImGui::TableSetColumnIndex(5);
                if (pkt.src_port > 0)
                    ImGui::Text("%d -> %d", pkt.src_port, pkt.dst_port);
                else
                    ImGui::Text("-");
                
                // Length
                ImGui::TableSetColumnIndex(6);
                ImGui::Text("%u bytes", pkt.length);
                
                // Info
                ImGui::TableSetColumnIndex(7);
                ImGui::Text("%s", pkt.info.c_str());
                
                ImGui::PopStyleColor();
            }
        }
        
        if (g_AutoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
            ImGui::SetScrollHereY(1.0f);
        }
        
        ImGui::EndTable();
    }
    
    ImGui::End();
}

// ============== Packet Details Panel ==============
void renderPacketDetails() {
    if (g_SelectedPacket < 0) return;
    
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    
    ImGui::SetNextWindowPos(ImVec2(viewport->Pos.x + 380, viewport->Pos.y + viewport->Size.y - 480));
    ImGui::SetNextWindowSize(ImVec2(viewport->Size.x - 380, 420));
    
    ImGui::Begin("Packet Details", nullptr,
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse);
    
    auto packets = g_PacketBuffer.getPackets();
    const PacketInfo* p = nullptr;
    for (const auto& pkt : packets) {
        if (pkt.id == g_SelectedPacket) {
            p = &pkt;
            break;
        }
    }
    
    if (!p) {
        ImGui::Text("Packet not found in buffer");
        ImGui::End();
        return;
    }
    
    // Two columns layout
    ImGui::Columns(2, "DetailCols", true);
    ImGui::SetColumnWidth(0, 550);
    
    // === Left: Protocol Tree ===
    ImGui::BeginChild("ProtocolTree", ImVec2(0, 0), true);
    
    // Frame Information
    if (ImGui::TreeNodeEx("Frame", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Packet Number:"); ImGui::SameLine(200); ImGui::Text("%d", p->id);
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Arrival Time:"); ImGui::SameLine(200); ImGui::Text("%.6f", p->timestamp);
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Frame Length:"); ImGui::SameLine(200); ImGui::Text("%u bytes", p->length);
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Capture Length:"); ImGui::SameLine(200); ImGui::Text("%zu bytes", p->raw_data.size());
        ImGui::TreePop();
    }
    
    // Ethernet II
    if (p->has_ethernet && ImGui::TreeNodeEx("Ethernet II", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Destination:"); ImGui::SameLine(200); ImGui::Text("%s", p->ethernet.dst_mac.c_str());
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Source:"); ImGui::SameLine(200); ImGui::Text("%s", p->ethernet.src_mac.c_str());
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Type:"); ImGui::SameLine(200); ImGui::Text("0x%04X (%s)", p->ethernet.ether_type, p->ethernet.ether_type_name.c_str());
        ImGui::TreePop();
    }
    
    // ARP
    if (p->has_arp && ImGui::TreeNodeEx("Address Resolution Protocol (ARP)", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Operation:"); ImGui::SameLine(200); ImGui::Text("%s (%d)", p->arp.operation_name.c_str(), p->arp.operation);
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Sender MAC:"); ImGui::SameLine(200); ImGui::Text("%s", p->arp.sender_mac.c_str());
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Sender IP:"); ImGui::SameLine(200); ImGui::Text("%s", p->arp.sender_ip.c_str());
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Target MAC:"); ImGui::SameLine(200); ImGui::Text("%s", p->arp.target_mac.c_str());
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Target IP:"); ImGui::SameLine(200); ImGui::Text("%s", p->arp.target_ip.c_str());
        ImGui::TreePop();
    }
    
    // IPv4
    if (p->has_ipv4 && ImGui::TreeNodeEx("Internet Protocol Version 4", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Version:"); ImGui::SameLine(200); ImGui::Text("%d", p->ipv4.version);
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Header Length:"); ImGui::SameLine(200); ImGui::Text("%d bytes", p->ipv4.ihl);
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Total Length:"); ImGui::SameLine(200); ImGui::Text("%d bytes", p->ipv4.total_length);
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Identification:"); ImGui::SameLine(200); ImGui::Text("0x%04X (%d)", p->ipv4.identification, p->ipv4.identification);
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Flags:"); ImGui::SameLine(200); 
        ImGui::Text("DF=%d, MF=%d", p->ipv4.df_flag ? 1 : 0, p->ipv4.mf_flag ? 1 : 0);
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Fragment Offset:"); ImGui::SameLine(200); ImGui::Text("%d", p->ipv4.fragment_offset);
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Time to Live:"); ImGui::SameLine(200); ImGui::Text("%d", p->ipv4.ttl);
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Protocol:"); ImGui::SameLine(200); ImGui::Text("%s (%d)", p->ipv4.protocol_name.c_str(), p->ipv4.protocol);
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Header Checksum:"); ImGui::SameLine(200); ImGui::Text("0x%04X", p->ipv4.checksum);
        ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.4f, 1.0f), "Source IP:"); ImGui::SameLine(200); ImGui::Text("%s", p->ipv4.src_ip.c_str());
        ImGui::TextColored(ImVec4(0.9f, 0.4f, 0.4f, 1.0f), "Destination IP:"); ImGui::SameLine(200); ImGui::Text("%s", p->ipv4.dst_ip.c_str());
        ImGui::TreePop();
    }
    
    // ICMP
    if (p->has_icmp && ImGui::TreeNodeEx("Internet Control Message Protocol", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Type:"); ImGui::SameLine(200); ImGui::Text("%d (%s)", p->icmp.type, p->icmp.type_name.c_str());
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Code:"); ImGui::SameLine(200); ImGui::Text("%d", p->icmp.code);
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Checksum:"); ImGui::SameLine(200); ImGui::Text("0x%04X", p->icmp.checksum);
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Identifier:"); ImGui::SameLine(200); ImGui::Text("%d (0x%04X)", p->icmp.identifier, p->icmp.identifier);
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Sequence:"); ImGui::SameLine(200); ImGui::Text("%d", p->icmp.sequence);
        ImGui::TreePop();
    }
    
    // TCP
    if (p->has_tcp && ImGui::TreeNodeEx("Transmission Control Protocol", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.4f, 1.0f), "Source Port:"); ImGui::SameLine(200); ImGui::Text("%d", p->tcp.src_port);
        ImGui::TextColored(ImVec4(0.9f, 0.4f, 0.4f, 1.0f), "Destination Port:"); ImGui::SameLine(200); ImGui::Text("%d", p->tcp.dst_port);
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Sequence Number:"); ImGui::SameLine(200); ImGui::Text("%u", p->tcp.seq_num);
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Acknowledgment:"); ImGui::SameLine(200); ImGui::Text("%u", p->tcp.ack_num);
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Header Length:"); ImGui::SameLine(200); ImGui::Text("%d bytes", p->tcp.data_offset);
        ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), "Flags:"); ImGui::SameLine(200); ImGui::Text("[%s]", p->tcp.flags_str.c_str());
        
        // Show individual flags
        ImGui::Indent(20);
        ImGui::TextColored(p->tcp.flags.SYN ? ImVec4(0.3f, 1.0f, 0.3f, 1.0f) : ImVec4(0.4f, 0.4f, 0.4f, 1.0f), "SYN: %d", p->tcp.flags.SYN);
        ImGui::SameLine(); ImGui::TextColored(p->tcp.flags.ACK ? ImVec4(0.3f, 1.0f, 0.3f, 1.0f) : ImVec4(0.4f, 0.4f, 0.4f, 1.0f), "  ACK: %d", p->tcp.flags.ACK);
        ImGui::SameLine(); ImGui::TextColored(p->tcp.flags.FIN ? ImVec4(1.0f, 0.5f, 0.3f, 1.0f) : ImVec4(0.4f, 0.4f, 0.4f, 1.0f), "  FIN: %d", p->tcp.flags.FIN);
        ImGui::SameLine(); ImGui::TextColored(p->tcp.flags.RST ? ImVec4(1.0f, 0.3f, 0.3f, 1.0f) : ImVec4(0.4f, 0.4f, 0.4f, 1.0f), "  RST: %d", p->tcp.flags.RST);
        ImGui::TextColored(p->tcp.flags.PSH ? ImVec4(0.3f, 0.8f, 1.0f, 1.0f) : ImVec4(0.4f, 0.4f, 0.4f, 1.0f), "PSH: %d", p->tcp.flags.PSH);
        ImGui::SameLine(); ImGui::TextColored(p->tcp.flags.URG ? ImVec4(1.0f, 0.8f, 0.3f, 1.0f) : ImVec4(0.4f, 0.4f, 0.4f, 1.0f), "  URG: %d", p->tcp.flags.URG);
        ImGui::Unindent(20);
        
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Window Size:"); ImGui::SameLine(200); ImGui::Text("%d", p->tcp.window);
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Checksum:"); ImGui::SameLine(200); ImGui::Text("0x%04X", p->tcp.checksum);
        ImGui::TreePop();
    }
    
    // UDP
    if (p->has_udp && ImGui::TreeNodeEx("User Datagram Protocol", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.4f, 1.0f), "Source Port:"); ImGui::SameLine(200); ImGui::Text("%d", p->udp.src_port);
        ImGui::TextColored(ImVec4(0.9f, 0.4f, 0.4f, 1.0f), "Destination Port:"); ImGui::SameLine(200); ImGui::Text("%d", p->udp.dst_port);
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Length:"); ImGui::SameLine(200); ImGui::Text("%d bytes", p->udp.length);
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Checksum:"); ImGui::SameLine(200); ImGui::Text("0x%04X", p->udp.checksum);
        ImGui::TreePop();
    }
    
    // DNS
    if (p->has_dns && ImGui::TreeNodeEx("Domain Name System (DNS)", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Transaction ID:"); ImGui::SameLine(200); ImGui::Text("0x%04X", p->dns.transaction_id);
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Type:"); ImGui::SameLine(200); ImGui::Text("%s", p->dns.is_query ? "Query" : "Response");
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Questions:"); ImGui::SameLine(200); ImGui::Text("%d", p->dns.questions);
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Answers:"); ImGui::SameLine(200); ImGui::Text("%d", p->dns.answers);
        
        if (!p->dns.queries.empty()) {
            ImGui::TextColored(ImVec4(0.4f, 0.85f, 1.0f, 1.0f), "Queries:");
            for (const auto& q : p->dns.queries) {
                ImGui::Indent(20);
                ImGui::BulletText("%s", q.c_str());
                ImGui::Unindent(20);
            }
        }
        if (!p->dns.responses.empty()) {
            ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.6f, 1.0f), "Answers:");
            for (const auto& r : p->dns.responses) {
                ImGui::Indent(20);
                ImGui::BulletText("%s", r.c_str());
                ImGui::Unindent(20);
            }
        }
        ImGui::TreePop();
    }
    
    // HTTP
    if (p->has_http && ImGui::TreeNodeEx("Hypertext Transfer Protocol", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (p->http.is_request) {
            ImGui::TextColored(ImVec4(0.3f, 0.9f, 1.0f, 1.0f), "HTTP Request");
            ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Method:"); ImGui::SameLine(200); ImGui::Text("%s", p->http.method.c_str());
            ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "URI:"); ImGui::SameLine(200); ImGui::Text("%s", p->http.uri.c_str());
            ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Version:"); ImGui::SameLine(200); ImGui::Text("%s", p->http.version.c_str());
            if (!p->http.host.empty()) {
                ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Host:"); ImGui::SameLine(200); ImGui::Text("%s", p->http.host.c_str());
            }
            if (!p->http.user_agent.empty()) {
                ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "User-Agent:"); ImGui::SameLine(200); ImGui::Text("%s", p->http.user_agent.c_str());
            }
        } else if (p->http.is_response) {
            ImGui::TextColored(ImVec4(0.9f, 0.6f, 0.3f, 1.0f), "HTTP Response");
            ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Version:"); ImGui::SameLine(200); ImGui::Text("%s", p->http.version.c_str());
            ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Status Code:"); ImGui::SameLine(200); ImGui::Text("%d", p->http.status_code);
            ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Status:"); ImGui::SameLine(200); ImGui::Text("%s", p->http.status_text.c_str());
            if (!p->http.content_type.empty()) {
                ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Content-Type:"); ImGui::SameLine(200); ImGui::Text("%s", p->http.content_type.c_str());
            }
        }
        ImGui::TreePop();
    }
    
    ImGui::EndChild();
    
    // === Right: Hex Dump ===
    ImGui::NextColumn();
    
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.85f, 1.0f, 1.0f));
    ImGui::Text("RAW DATA (HEX DUMP)");
    ImGui::PopStyleColor();
    ImGui::Separator();
    
    ImGui::BeginChild("HexView", ImVec2(0, 0), true);
    
    for (size_t i = 0; i < p->raw_data.size(); i += 16) {
        ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), "%04zx  ", i);
        ImGui::SameLine();
        
        std::string hex, ascii;
        for (size_t j = 0; j < 16; j++) {
            if (i + j < p->raw_data.size()) {
                uint8_t b = p->raw_data[i + j];
                char h[4];
                sprintf(h, "%02x ", b);
                hex += h;
                ascii += (b >= 32 && b < 127) ? (char)b : '.';
            } else {
                hex += "   ";
                ascii += " ";
            }
            if (j == 7) hex += " ";
        }
        
        ImGui::TextColored(ImVec4(0.95f, 0.9f, 0.6f, 1.0f), "%s", hex.c_str());
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.6f, 0.95f, 0.6f, 1.0f), " %s", ascii.c_str());
    }
    
    ImGui::EndChild();
    ImGui::Columns(1);
    ImGui::End();
}

// ============== Status Bar ==============
void renderStatusBar() {
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    
    ImGui::SetNextWindowPos(ImVec2(viewport->Pos.x, viewport->Pos.y + viewport->Size.y - 60));
    ImGui::SetNextWindowSize(ImVec2(viewport->Size.x, 60));
    
    ImGui::Begin("##StatusBar", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoBringToFrontOnFocus);
    
    ImGui::SetCursorPosY(15);
    ImGui::SetCursorPosX(25);
    
    // Status message
    if (g_StatusIsError) {
        ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%s", g_StatusMessage.c_str());
    } else {
        ImGui::TextColored(ImVec4(0.5f, 0.85f, 0.5f, 1.0f), "%s", g_StatusMessage.c_str());
    }
    
    // Right side info
    ImGui::SameLine(viewport->Size.x - 500);
    
    if (g_Capture.isRunning()) {
        ImGui::TextColored(ImVec4(0.3f, 0.95f, 0.4f, 1.0f), ">>> LIVE <<<");
    } else {
        ImGui::TextColored(ImVec4(0.55f, 0.55f, 0.55f, 1.0f), "   IDLE");
    }
    
    ImGui::SameLine();
    ImGui::Text(" | Packets: %zu", g_PacketBuffer.size());
    
    auto devices = PacketCapture::getDevices();
    if (g_SelectedDevice < (int)devices.size()) {
        ImGui::SameLine();
        std::string ifName = devices[g_SelectedDevice].second;
        if (ifName.length() > 35) ifName = ifName.substr(0, 35) + "...";
        ImGui::Text(" | %s", ifName.c_str());
    }
    
    ImGui::End();
}

// ============== TCP Stream Window ==============
void renderTCPStreamWindow() {
    if (!g_ShowStreamWindow) return;
    
    ImGui::SetNextWindowSize(ImVec2(900, 700), ImGuiCond_FirstUseEver);
    
    if (!ImGui::Begin("TCP Stream Viewer", &g_ShowStreamWindow, ImGuiWindowFlags_NoCollapse)) {
        ImGui::End();
        return;
    }
    
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.85f, 1.0f, 1.0f));
    ImGui::Text("TCP STREAM ANALYSIS");
    ImGui::PopStyleColor();
    ImGui::Separator();
    ImGui::Spacing();
    
    // Stream info
    ImGui::Text("Stream: %s", g_SelectedStream.key.toString().c_str());
    ImGui::Text("Packets: %d", g_SelectedStream.packet_count);
    ImGui::Text("Duration: %.3f seconds", g_SelectedStream.end_time - g_SelectedStream.start_time);
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    
    // Tabs for different views
    if (ImGui::BeginTabBar("StreamTabs")) {
        
        // Client -> Server Tab
        if (ImGui::BeginTabItem("Client -> Server")) {
            ImGui::Text("Data size: %zu bytes", g_SelectedStream.client_to_server_data.size());
            ImGui::Separator();
            
            ImGui::BeginChild("ClientData", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
            
            // Try to show as text
            bool is_text = true;
            for (uint8_t byte : g_SelectedStream.client_to_server_data) {
                if (byte < 32 && byte != '\n' && byte != '\r' && byte != '\t') {
                    if (byte > 0) {
                        is_text = false;
                        break;
                    }
                }
            }
            
            if (is_text && !g_SelectedStream.client_to_server_data.empty()) {
                std::string text;
                for (uint8_t byte : g_SelectedStream.client_to_server_data) {
                    if (byte >= 32 && byte <= 126) {
                        text += (char)byte;
                    } else if (byte == '\n') {
                        text += '\n';
                    } else if (byte == '\r') {
                        // skip
                    } else {
                        text += '.';
                    }
                }
                ImGui::TextWrapped("%s", text.c_str());
            } else {
                // Show hex dump
                for (size_t i = 0; i < g_SelectedStream.client_to_server_data.size(); i += 16) {
                    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), "%04zx  ", i);
                    ImGui::SameLine();
                    
                    std::string hex, ascii;
                    for (size_t j = 0; j < 16; j++) {
                        if (i + j < g_SelectedStream.client_to_server_data.size()) {
                            uint8_t b = g_SelectedStream.client_to_server_data[i + j];
                            char h[4];
                            sprintf(h, "%02x ", b);
                            hex += h;
                            ascii += (b >= 32 && b < 127) ? (char)b : '.';
                        } else {
                            hex += "   ";
                        }
                        if (j == 7) hex += " ";
                    }
                    
                    ImGui::TextColored(ImVec4(0.95f, 0.9f, 0.6f, 1.0f), "%s", hex.c_str());
                    ImGui::SameLine();
                    ImGui::TextColored(ImVec4(0.6f, 0.95f, 0.6f, 1.0f), " %s", ascii.c_str());
                }
            }
            
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        
        // Server -> Client Tab
        if (ImGui::BeginTabItem("Server -> Client")) {
            ImGui::Text("Data size: %zu bytes", g_SelectedStream.server_to_client_data.size());
            ImGui::Separator();
            
            ImGui::BeginChild("ServerData", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
            
            // Try to show as text
            bool is_text = true;
            for (uint8_t byte : g_SelectedStream.server_to_client_data) {
                if (byte < 32 && byte != '\n' && byte != '\r' && byte != '\t') {
                    if (byte > 0) {
                        is_text = false;
                        break;
                    }
                }
            }
            
            if (is_text && !g_SelectedStream.server_to_client_data.empty()) {
                std::string text;
                for (uint8_t byte : g_SelectedStream.server_to_client_data) {
                    if (byte >= 32 && byte <= 126) {
                        text += (char)byte;
                    } else if (byte == '\n') {
                        text += '\n';
                    } else if (byte == '\r') {
                        // skip
                    } else {
                        text += '.';
                    }
                }
                ImGui::TextWrapped("%s", text.c_str());
            } else {
                // Show hex dump
                for (size_t i = 0; i < g_SelectedStream.server_to_client_data.size(); i += 16) {
                    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), "%04zx  ", i);
                    ImGui::SameLine();
                    
                    std::string hex, ascii;
                    for (size_t j = 0; j < 16; j++) {
                        if (i + j < g_SelectedStream.server_to_client_data.size()) {
                            uint8_t b = g_SelectedStream.server_to_client_data[i + j];
                            char h[4];
                            sprintf(h, "%02x ", b);
                            hex += h;
                            ascii += (b >= 32 && b < 127) ? (char)b : '.';
                        } else {
                            hex += "   ";
                        }
                        if (j == 7) hex += " ";
                    }
                    
                    ImGui::TextColored(ImVec4(0.95f, 0.9f, 0.6f, 1.0f), "%s", hex.c_str());
                    ImGui::SameLine();
                    ImGui::TextColored(ImVec4(0.6f, 0.95f, 0.6f, 1.0f), " %s", ascii.c_str());
                }
            }
            
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        
        // Export Tab
        if (ImGui::BeginTabItem("Export")) {
            ImGui::Spacing();
            
            if (ImGui::Button("Save as Text File", ImVec2(250, 40))) {
                auto now = std::chrono::system_clock::now();
                auto time = std::chrono::system_clock::to_time_t(now);
                struct tm timeinfo;
                localtime_s(&timeinfo, &time);
                char defaultName[100];
                sprintf_s(defaultName, sizeof(defaultName), "tcp_stream_%04d%02d%02d_%02d%02d%02d.txt",
                         timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
                         timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
                
                std::string filename = openSaveFileDialog(g_Window,
                    "Text Files (*.txt)\0*.txt\0All Files (*.*)\0*.*\0",
                    "txt", defaultName);
                
                if (!filename.empty()) {
                    std::ofstream file(filename);
                    if (file.is_open()) {
                        file << g_SelectedStream.toText();
                        file.close();
                        g_StatusMessage = "Stream saved to " + filename;
                        g_StatusIsError = false;
                    } else {
                        g_StatusMessage = "ERROR: Failed to save stream";
                        g_StatusIsError = true;
                    }
                }
            }
            
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();
            
            ImGui::TextWrapped("This will export the full TCP stream conversation to a text file with hex dump and ASCII representation.");
            
            ImGui::EndTabItem();
        }
        
        ImGui::EndTabBar();
    }
    
    ImGui::End();
}

// ============== Main Entry Point ==============
int main() {
    if (!glfwInit()) return -1;
    
    const char* glsl_version = "#version 330";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_MAXIMIZED, GLFW_TRUE);
    
    GLFWwindow* window = glfwCreateWindow(1920, 1080, "Network Packet Analyzer - Professional Edition", NULL, NULL);
    if (!window) {
        glfwTerminate();
        return -1;
    }
    
    g_Window = window;  // Set global window pointer for file dialogs
    
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);
    
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    
    // Load system font - large size
    io.Fonts->AddFontFromFileTTF("C:/Windows/Fonts/segoeui.ttf", 20.0f);
    io.FontGlobalScale = 1.0f;
    
    setupDarkTheme();
    
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);
    
    // Main loop
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();
        
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();
        
        renderTitleBar();
        renderControlPanel();
        renderPacketList();
        renderPacketDetails();
        renderTCPStreamWindow();
        renderStatusBar();
        
        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.06f, 0.06f, 0.08f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        
        glfwSwapBuffers(window);
    }
    
    g_Capture.stop();
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    
    return 0;
}
