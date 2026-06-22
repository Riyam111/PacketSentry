#include "live_capture.h"
#include <iostream>
#include <iomanip>

namespace PacketAnalyzer {

void LiveCapture::listInterfaces() {
    pcap_if_t* alldevs = nullptr;// linked list o f network interfaces
    char errbuf[PCAP_ERRBUF_SIZE];//store error msg

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "[LiveCapture] Cannot list interfaces: " << errbuf << "\n";
        return;
    }

    std::cout << "\nAvailable network interfaces:\n";
    std::cout << std::string(60, '-') << "\n";

    int idx = 0;
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        std::cout << "[" << idx++ << "] " << d->name << "\n";
        if (d->description)
            std::cout << "     " << d->description << "\n";
        // Print IP addresses for easier identification
        for (pcap_addr_t* a = d->addresses; a != nullptr; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                char ip[INET_ADDRSTRLEN];
                struct sockaddr_in* sin = (struct sockaddr_in*)a->addr;
                inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));//convert binary IP to string
                std::cout << "     IPv4: " << ip << "\n";
            }
        }
    }
    std::cout << std::string(60, '-') << "\n\n"; // end of list
    pcap_freealldevs(alldevs); // free the linked list
}

bool LiveCapture::open(const std::string& iface, int snaplen,
                       int timeout_ms, bool promiscuous) {
    char errbuf[PCAP_ERRBUF_SIZE];
// Open the interface for live capture
    handle_ = pcap_open_live(
        iface.c_str(),// device name
        snaplen,// max bytes per packet
        promiscuous ? 1 : 0,
        timeout_ms,
        errbuf
    );

    if (!handle_) {
        std::cerr << "[LiveCapture] Failed to open '" << iface << "': "
                  << errbuf << "\n";
        std::cerr << "  Tip: Run as Administrator and check the interface name.\n";
        return false;
    }

    // Verify it's Ethernet (link type 1) — same as your pcap files
    int linktype = pcap_datalink(handle_);
    if (linktype != DLT_EN10MB) {
        std::cerr << "[LiveCapture] Warning: link type is " << linktype
                  << " (not Ethernet). Packet parsing may fail.\n";
    }

    std::cout << "[LiveCapture] Opened: " << iface << "\n";
    return true;
}
// BPF filter string e.g. "tcp port 443" or "tcp or udp"
bool LiveCapture::setFilter(const std::string& filter_expr) {
    if (!handle_) return false;

    struct bpf_program fp;
    // PCAP_NETMASK_UNKNOWN is fine for most filters
    if (pcap_compile(handle_, &fp, filter_expr.c_str(),
                     1, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "[LiveCapture] Filter compile error: "
                  << pcap_geterr(handle_) << "\n";
        return false;
    }
    if (pcap_setfilter(handle_, &fp) == -1) {
        std::cerr << "[LiveCapture] Filter apply error: "
                  << pcap_geterr(handle_) << "\n";
        pcap_freecode(&fp);
        return false;
    }
    pcap_freecode(&fp);// Free the compiled filter
    std::cout << "[LiveCapture] BPF filter: \"" << filter_expr << "\"\n";
    return true;
}

void LiveCapture::startCapture(PacketCallback callback) {
    if (!handle_) return;
    running_ = true;

    struct pcap_pkthdr* header = nullptr;//it contains metadata about the captured packet, such as timestamp and length
    const u_char*       data   = nullptr; // pointer to the actual packet data

    while (running_) {
        //it return next packet
        int ret = pcap_next_ex(handle_, &header, &data);// returns 1 for success, 0 for timeout, -1 for error, -2 for EOF

        if (ret == 0)              continue;  // timeout, loop again
        if (ret == PCAP_ERROR_BREAK) break;   // pcap_breakloop() called
        if (ret < 0)               break;     // real error

        // Build a RawPacket — same struct your existing pipeline uses
        RawPacket pkt;
        pkt.header.ts_sec   = static_cast<uint32_t>(header->ts.tv_sec);
        pkt.header.ts_usec  = static_cast<uint32_t>(header->ts.tv_usec);
        pkt.header.incl_len = header->caplen;
        pkt.header.orig_len = header->len;
        pkt.data.assign(data, data + header->caplen);

        callback(pkt);   // hand off to your existing DPI pipeline
    }

    running_ = false;
}

void LiveCapture::stop() {
    running_ = false;
    if (handle_)
        pcap_breakloop(handle_);   // breaks out of pcap_next_ex cleanly
}

void LiveCapture::close() {
    stop();
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

} // namespace PacketAnalyzer