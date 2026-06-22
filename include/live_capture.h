#ifndef LIVE_CAPTURE_H
#define LIVE_CAPTURE_H

#include <pcap.h>
#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include "pcap_reader.h"   // reuses your RawPacket struct

namespace PacketAnalyzer {

class LiveCapture {
public:
    using PacketCallback = std::function<void(const RawPacket&)>;

    LiveCapture() = default;
    ~LiveCapture() { close(); }

    // Print all available interfaces with friendly names
    static void listInterfaces();

    // iface on Windows looks like: \Device\NPF_{GUID-HERE}
    // snaplen = max bytes per packet, timeout_ms = read timeout
    bool open(const std::string& iface,
              int snaplen     = 65535,
              int timeout_ms  = 1000,
              bool promiscuous = true);

    // BPF filter string e.g. "tcp port 443" or "tcp or udp"
    bool setFilter(const std::string& filter_expr);

    // Blocking call — runs until stop() is called from another thread
    void startCapture(PacketCallback callback);

    // Call from another thread to stop the capture loop
    void stop();

    void close();

    bool isOpen() const { return handle_ != nullptr; }

private:
    pcap_t*           handle_  = nullptr;
    std::atomic<bool> running_ = false;
};

} // namespace PacketAnalyzer
#endif