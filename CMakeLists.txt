cmake_minimum_required(VERSION 3.10)
project(PacketCaptureGUI VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(WIN32)
    add_definitions(-DNOMINMAX -D_WIN32_WINNT=0x0601)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Npcap
if(WIN32)
    set(PCAP_INCLUDE_DIR "C:/npcap-sdk/Include")
    set(PCAP_LIBRARY "C:/npcap-sdk/Lib/x64/wpcap.lib")
    
    if(NOT EXISTS ${PCAP_INCLUDE_DIR})
        message(FATAL_ERROR "Npcap SDK not found at ${PCAP_INCLUDE_DIR}")
    endif()
endif()

include_directories(${PCAP_INCLUDE_DIR})

# ImGui + GLFW + OpenGL
set(IMGUI_DIR "${CMAKE_CURRENT_SOURCE_DIR}/external/imgui")
set(GLFW_DIR "${CMAKE_CURRENT_SOURCE_DIR}/external/glfw")

# Download ImGui if not exists
if(NOT EXISTS ${IMGUI_DIR})
    message(STATUS "Downloading Dear ImGui...")
    file(DOWNLOAD 
        "https://github.com/ocornut/imgui/archive/refs/tags/v1.90.1.zip"
        "${CMAKE_CURRENT_BINARY_DIR}/imgui.zip"
        SHOW_PROGRESS
    )
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E tar xf "${CMAKE_CURRENT_BINARY_DIR}/imgui.zip"
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/external"
    )
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/external/imgui-1.90.1")
        file(RENAME "${CMAKE_CURRENT_SOURCE_DIR}/external/imgui-1.90.1" ${IMGUI_DIR})
    endif()
endif()

# GLFW
set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)

if(NOT EXISTS ${GLFW_DIR})
    message(STATUS "Downloading GLFW...")
    file(DOWNLOAD
        "https://github.com/glfw/glfw/releases/download/3.3.9/glfw-3.3.9.zip"
        "${CMAKE_CURRENT_BINARY_DIR}/glfw.zip"
        SHOW_PROGRESS
    )
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E tar xf "${CMAKE_CURRENT_BINARY_DIR}/glfw.zip"
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/external"
    )
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/external/glfw-3.3.9")
        file(RENAME "${CMAKE_CURRENT_SOURCE_DIR}/external/glfw-3.3.9" ${GLFW_DIR})
    endif()
endif()

add_subdirectory(${GLFW_DIR})

# ImGui sources
set(IMGUI_SOURCES
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_demo.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp
    ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
)

include_directories(
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
    ${GLFW_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Application sources
set(APP_SOURCES
    src/main.cpp
    src/packet_capture.cpp
)

add_executable(PacketCaptureGUI 
    ${APP_SOURCES}
    ${IMGUI_SOURCES}
)

target_link_libraries(PacketCaptureGUI
    ${PCAP_LIBRARY}
    glfw
    opengl32
    ws2_32
)

message(STATUS "PCAP Include: ${PCAP_INCLUDE_DIR}")
message(STATUS "PCAP Library: ${PCAP_LIBRARY}")
message(STATUS "ImGui Dir: ${IMGUI_DIR}")
message(STATUS "GLFW Dir: ${GLFW_DIR}")
