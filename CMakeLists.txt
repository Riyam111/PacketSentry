cmake_minimum_required(VERSION 3.16)
project(PacketAnalyzer VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# Tell CMake to output the finished .exe to the main project folder
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}")
# Npcap SDK path
set(NPCAP_SDK_DIR "C:/Users/riyam/Downloads/npcap-sdk-1.16")

# Source files
set(SOURCES
    src/main.cpp
    src/live_capture.cpp          # <-- ADD THIS LINE
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/connection_tracker.cpp   # <-- ADD THIS LINE
    src/types.cpp
    src/load_balancer.cpp
    src/fast_path.cpp
    src/rule_manager.cpp
    src/statistics_aggregator.cpp
)

# Header files location
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${NPCAP_SDK_DIR}/Include
)

# Library directories
link_directories(
    ${NPCAP_SDK_DIR}/Lib/x64
)
# Create the executable
add_executable(packet_analyzer ${SOURCES})

# Link Npcap libraries
target_link_libraries(packet_analyzer
    wpcap
    Packet
   # ws2_32
)

# Windows-specific defines to avoid header conflicts   <-- ADD THIS BLOCK
if(WIN32)
    target_compile_definitions(packet_analyzer
        PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX
    )
endif()

# For macOS, we might need to link against system libraries later
if(APPLE)
    # Add any macOS-specific settings here
endif()