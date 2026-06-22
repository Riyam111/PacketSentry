#include <iostream>
#include <iomanip>
#include <ctime>
#include <atomic>
#include <thread>
#include <chrono>
#include <csignal>
#include "pcap_reader.h"
#include "packet_parser.h"
#include "live_capture.h"   // your new file
#include "sni_extractor.h"
#include "connection_tracker.h"  // <--- NEW
#include <winsock2.h>
#include <chrono>
#include "load_balancer.h"
#include "fast_path.h"
#include <thread>
#include <vector>
#include <memory>
#include "statistics_aggregator.h"
#include <fstream>


using namespace PacketAnalyzer;

// ─────────────────────────────────────────────────────────────
// Ctrl+C handler for live mode
// ─────────────────────────────────────────────────────────────
static std::atomic<bool> g_running{true};
static DPI::ConnectionTracker g_tracker(0);
static DPI::GlobalConnectionTable g_global_table(1); 
static std::chrono::steady_clock::time_point last_report_time = std::chrono::steady_clock::now();
// ---------------------------------------------

void signalHandler(int) {
    g_running = false;
}

// ─────────────────────────────────────────────────────────────
// Packet display (your original code — unchanged)
// ─────────────────────────────────────────────────────────────
void printPacketSummary(const ParsedPacket& pkt, int packet_num) {
    std::time_t time = pkt.timestamp_sec;
    std::tm* tm = std::localtime(&time);

    std::cout << "\n========== Packet #" << packet_num << " ==========\n";
    std::cout << "Time: " << std::put_time(tm, "%Y-%m-%d %H:%M:%S")
              << "." << std::setfill('0') << std::setw(6) << pkt.timestamp_usec << "\n";

    // Ethernet layer
    std::cout << "\n[Ethernet]\n";
    std::cout << "  Source MAC:      " << pkt.src_mac << "\n";
    std::cout << "  Destination MAC: " << pkt.dest_mac << "\n";
    std::cout << "  EtherType:       0x" << std::hex << std::setfill('0')
              << std::setw(4) << pkt.ether_type << std::dec;

    if      (pkt.ether_type == EtherType::IPv4) std::cout << " (IPv4)";
    else if (pkt.ether_type == EtherType::IPv6) std::cout << " (IPv6)";
    else if (pkt.ether_type == EtherType::ARP)  std::cout << " (ARP)";
    std::cout << "\n";

    // IP layer
    if (pkt.has_ip) {
        std::cout << "\n[IPv" << static_cast<int>(pkt.ip_version) << "]\n";
        std::cout << "  Source IP:      " << pkt.src_ip << "\n";
        std::cout << "  Destination IP: " << pkt.dest_ip << "\n";
        std::cout << "  Protocol:       " << PacketParser::protocolToString(pkt.protocol) << "\n";
        std::cout << "  TTL:            " << static_cast<int>(pkt.ttl) << "\n";
    }

    // TCP layer
    if (pkt.has_tcp) {
        std::cout << "\n[TCP]\n";
        std::cout << "  Source Port:      " << pkt.src_port << "\n";
        std::cout << "  Destination Port: " << pkt.dest_port << "\n";
        std::cout << "  Sequence Number:  " << pkt.seq_number << "\n";
        std::cout << "  Ack Number:       " << pkt.ack_number << "\n";
        std::cout << "  Flags:            " << PacketParser::tcpFlagsToString(pkt.tcp_flags) << "\n";
    }

    // UDP layer
    if (pkt.has_udp) {
        std::cout << "\n[UDP]\n";
        std::cout << "  Source Port:      " << pkt.src_port << "\n";
        std::cout << "  Destination Port: " << pkt.dest_port << "\n";
    }

    // Payload
    if (pkt.payload_length > 0) {
        std::cout << "\n[Payload]\n";
        std::cout << "  Length: " << pkt.payload_length << " bytes\n";
        std::cout << "  Preview: ";
        size_t preview_len = std::min(pkt.payload_length, static_cast<size_t>(32));
        for (size_t i = 0; i < preview_len; i++) {
            std::cout << std::hex << std::setfill('0') << std::setw(2)
                      << static_cast<int>(pkt.payload_data[i]) << " ";
        }
        if (pkt.payload_length > 32) std::cout << "...";
        std::cout << std::dec << "\n";
    }
}

// ─────────────────────────────────────────────────────────────
// Shared packet processor — same logic for both modes
// ─────────────────────────────────────────────────────────────
void processRawPacket(const RawPacket& raw, int& packet_count, int& parse_errors) {
    auto now = std::chrono::steady_clock::now();
    auto time_since_report = std::chrono::duration_cast<std::chrono::seconds>(now - last_report_time);

    // Print dashboard every 10 seconds
    if (time_since_report.count() >= 10) {
        last_report_time = now;
        
        // Clean up connections that have been dead for 5 minutes (300 seconds)
        size_t removed = g_tracker.cleanupStale(std::chrono::seconds(300));
        
        std::cout << g_global_table.generateReport();
        std::cout << "║ [Cleanup] Removed " << removed << " stale connections.                 ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";
    }
    // -------------------------------------------------------------

    packet_count++;
    ParsedPacket parsed;
   
    
    if (PacketParser::parse(raw, parsed)) {
        
        // We only care about TCP flows for SNI tracking right now
        if (parsed.has_tcp) {
            
            // 1. Build the 5-Tuple to identify this specific flow
            DPI::FiveTuple tuple;
            tuple.src_ip = inet_addr(parsed.src_ip.c_str()); // Convert string IP to uint32_t
            tuple.dst_ip = inet_addr(parsed.dest_ip.c_str());
            tuple.src_port = parsed.src_port;
            tuple.dst_port = parsed.dest_port;
            tuple.protocol = 6; // TCP Protocol ID
            
            // 2. Fetch the connection from the tracking table (or create it if it's new)
            DPI::Connection* conn = g_tracker.getOrCreateConnection(tuple);
            
            // 3. Update the connection's data transfer stats
            g_tracker.updateConnection(conn, parsed.payload_length, true);
            
            // 4. Try to classify the connection if we haven't already!
            if (conn->state != DPI::ConnectionState::CLASSIFIED && parsed.payload_length > 0) {
                
                // Is this a TLS Handshake?
                if (parsed.payload_data[0] == 0x16) {
                    auto sni = DPI::SNIExtractor::extract(parsed.payload_data, parsed.payload_length);
                    
                    if (sni) {
                        // TAG THE FLOW: The tracker will now remember this SNI forever!
                       // Change it to this:
g_tracker.classifyConnection(conn, DPI::sniToAppType(*sni), *sni);
                        
                        std::cout << "\n=================================================\n";
                        std::cout << "[NEW FLOW] Application Detected: " << *sni << "\n";
                        std::cout << "[TRACKER]  Total Active Flows:   " << g_tracker.getActiveCount() << "\n";
                        std::cout << "=================================================\n";
                    }
                }
            }
            // If conn->state IS CLASSIFIED, we silently ignore the payload 
            // because we already know what application this is!
        }
        
    } else {
        parse_errors++;
    }
}

// ─────────────────────────────────────────────────────────────
// Usage
// ─────────────────────────────────────────────────────────────
void printUsage(const char* prog) {
    std::cout << "\nUsage:\n";
    std::cout << "  " << prog << " --list-interfaces\n";
    std::cout << "  " << prog << " --file <pcap_file> [max_packets]\n";
    std::cout << "  " << prog << " --live <interface> [max_packets]\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << prog << " --file capture.pcap\n";
    std::cout << "  " << prog << " --file capture.pcap 10\n";
    std::cout << "  " << prog << " --list-interfaces\n";
    std::cout << "  " << prog << " --live \"\\Device\\NPF_{GUID}\" 50\n\n";
}

// ─────────────────────────────────────────────────────────────
// Offline mode (your original logic, wrapped in a function)
// ─────────────────────────────────────────────────────────────
int runFileMode(const std::string& pcap_file, int max_pkts) {
    std::cout << "Starting OFFLINE analysis on: " << pcap_file << "\n";

    PacketAnalyzer::PcapReader capture;
    if (!capture.open(pcap_file)) {
        std::cerr << "Failed to open PCAP file.\n";
        return 1;
    }

    DPI::StatisticsAggregator stat_engine(1);
    
    // Use FPManager instead of raw FastPathProcessor so we can generate the ASCII report!
    DPI::FPManager fp_manager(1, nullptr, nullptr, &stat_engine);
    fp_manager.startAll();
// --- 1. UI UPDATER THREAD (For large files) ---
    std::thread json_broadcaster([&]() {
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            
            std::string payload = stat_engine.generateDashboardJSON();
            std::string file_path = "C:/Users/riyam/Documents/PacketSentry/live_data.json";
            
            std::ofstream out(file_path, std::ios::trunc);
            if (out.is_open()) {
                out << payload;
                out.close();
            }
        }
    });
    // ----------------------------------------------
    int packet_count = 0;
    RawPacket raw; 

    while (g_running && capture.readNextPacket(raw)) {
        if (max_pkts > 0 && packet_count >= max_pkts) {
            break; 
        }
        packet_count++;

        DPI::PacketJob job;
        job.packet_id = packet_count;
        job.data = raw.data;
        job.ts_sec = raw.header.ts_sec;
        job.ts_usec = raw.header.ts_usec;
        job.tuple = {0, 0, 0, 0, 0};

        PacketAnalyzer::ParsedPacket parsed;
        if (PacketAnalyzer::PacketParser::parse(raw, parsed) && parsed.has_tcp) {
            job.tuple.src_ip = inet_addr(parsed.src_ip.c_str());
            job.tuple.dst_ip = inet_addr(parsed.dest_ip.c_str());
            job.tuple.src_port = parsed.src_port;
            job.tuple.dst_port = parsed.dest_port;
            job.tuple.protocol = 6;
            job.payload_length = parsed.payload_length;
            if (parsed.payload_data != nullptr) {
                job.payload_offset = parsed.payload_data - raw.data.data();
            }
        }
        
        // Push job to the manager's queue
        fp_manager.getFPQueue(0).push(job);
    }

    std::cout << "Read " << packet_count << " packets from file. Waiting for worker to process...\n";
    
    // Give the background thread 500 milliseconds to process the queue
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    fp_manager.stopAll();
    g_running = false;
    if (json_broadcaster.joinable()) {
        json_broadcaster.join();
    }
// --- 3. FINAL JSON WRITE ---
    // Guarantees the dashboard sees the exact final numbers after the workers stop
    std::string final_payload = stat_engine.generateDashboardJSON();
    std::ofstream final_out("C:/Users/riyam/Documents/PacketSentry/live_data.json", std::ios::trunc);
    if (final_out.is_open()) {
        final_out << final_payload;
        final_out.close();
    }
    // ---------------------------
    // --- PRINT THE ASCII DASHBOARD ---
    std::cout << "\n" << fp_manager.generateClassificationReport();
    std::cout << "\n[Dashboard Updated] IPC File written successfully.\n";
    std::cout << "Analysis Complete.\n";
    return 0;}
// ─────────────────────────────────────────────────────────────
// Live mode (new)
// ─────────────────────────────────────────────────────────────
int runLiveMode(const std::string& interface_name, int max_pkts) {

    std::cout << "Starting SINGLE-THREADED live capture on: " << interface_name << "\n";



    PacketAnalyzer::LiveCapture capture;

    if (!capture.open(interface_name)) {

        return 1;

    }

    capture.setFilter("tcp port 443");



    DPI::StatisticsAggregator stat_engine(1);

   

   

    // --- CHANGE 1: Use FPManager with 1 thread to get the ASCII dashboard! ---

    DPI::FPManager fp_manager(1, nullptr, nullptr, &stat_engine);

    fp_manager.startAll();

    // -------------------------------------------------------------------------



   std::thread json_broadcaster([&]() {

        while (g_running) {

            std::this_thread::sleep_for(std::chrono::seconds(1));

           

            // Generate the JSON

            std::string payload = stat_engine.generateDashboardJSON();

            std::string file_path = "C:/Users/riyam/Documents/PacketSentry/live_data.json";

           std::ofstream out(file_path, std::ios::trunc);

            if (out.is_open()) {

                out << payload;

                out.close();

            }

           

            std::cout << "\n[JSON Saved] " << payload.substr(0, 80) << "...\n";

        }

    });



    int packet_count = 0;

    uint32_t global_packet_id = 0;

    auto last_report_time = std::chrono::steady_clock::now(); // Add our timer



    capture.startCapture([&](const RawPacket& raw) {

        if (!g_running || (max_pkts > 0 && packet_count >= max_pkts)) {

            capture.stop();

            g_running = false;

            return;

        }

        packet_count++;



        // --- CHANGE 2: Print the dashboard every 10 seconds! ---

        auto now = std::chrono::steady_clock::now();

        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_report_time).count() >= 10) {

            last_report_time = now;

            std::cout << fp_manager.generateClassificationReport();

        }

        // -------------------------------------------------------



        DPI::PacketJob job;

        job.packet_id = ++global_packet_id;

        job.data = raw.data;

        job.ts_sec = raw.header.ts_sec;

        job.ts_usec = raw.header.ts_usec;

       

        job.tuple.src_ip = 0;

        job.tuple.dst_ip = 0;

        job.tuple.src_port = 0;

        job.tuple.dst_port = 0;

        job.tuple.protocol = 0;



        PacketAnalyzer::ParsedPacket parsed;

        if (PacketAnalyzer::PacketParser::parse(raw, parsed) && parsed.has_tcp) {

            job.tuple.src_ip = inet_addr(parsed.src_ip.c_str());

            job.tuple.dst_ip = inet_addr(parsed.dest_ip.c_str());

            job.tuple.src_port = parsed.src_port;

            job.tuple.dst_port = parsed.dest_port;

            job.tuple.protocol = 6;

            job.payload_length = parsed.payload_length;

            if (parsed.payload_data != nullptr) {

                job.payload_offset = parsed.payload_data - raw.data.data();

            }

        }

       

        // Push the job to our single worker queue

        fp_manager.getFPQueue(0).push(job);

    });



    fp_manager.stopAll();

   

    if (json_broadcaster.joinable()) {

        json_broadcaster.join();

    }



    std::cout << "Analysis Complete.\n";

    return 0;

}

int runLiveModeMT(const std::string& iface, int num_threads) {

    std::cout << "\n=================================================\n";

    std::cout << "[Mode] MULTI-THREADED Live Capture: " << iface << "\n";

    std::cout << "       Fast Path Workers: " << num_threads << "\n";

    std::cout << "=================================================\n";



    // 1. Initialize the Fast Path Manager

    // Constructor expects: (num_fps, RuleManager*, PacketOutputCallback)

    // We pass nullptr for the callback since we just want it to analyze right now.

 

// 1. Initialize the Aggregator

    DPI::StatisticsAggregator stat_engine(num_threads);

   

    // 2. Pass it to the FPManager

    DPI::FPManager fp_manager(num_threads, nullptr, nullptr, &stat_engine);

    // 2. Gather the queues from the FPManager to give to the Load Balancer

    std::vector<DPI::ThreadSafeQueue<DPI::PacketJob>*> fp_queues;

    for (int i = 0; i < num_threads; ++i) {

        fp_queues.push_back(&fp_manager.getFPQueue(i));

    }



    // 3. Initialize the Load Balancer

    // Constructor expects: (lb_id, fp_queues, core_id)

    // We use 0 for the ID, and -1 to let the OS handle core affinity.

    DPI::LoadBalancer load_balancer(num_threads, fp_queues, 0);



    // 4. Start all the background threads!

    fp_manager.startAll();

    load_balancer.start(); // Assuming LoadBalancer has a start() method



    PacketAnalyzer::LiveCapture capture;

    if (!capture.open(iface)) return 1;

    capture.setFilter("tcp port 443");



    std::signal(SIGINT, signalHandler);

    auto last_report_time = std::chrono::steady_clock::now();



    // 5. The Capture Loop (Main Thread)

   

    // Add a counter before the loop

    uint32_t global_packet_id = 0;

// --- ADD THIS THREAD ---

    // --- ADD THIS THREAD ---

    std::thread json_broadcaster([&]() {

        while (g_running) {

            std::this_thread::sleep_for(std::chrono::seconds(1));

           

            // 1. Create the 'payload' variable by asking the engine for the JSON

            std::string payload = stat_engine.generateDashboardJSON();

            std::string file_path = "C:/Users/riyam/Documents/PacketSentry/live_data.json";

           

            std::ofstream out(file_path, std::ios::trunc);

            if (out.is_open()) {

                out << payload;

                out.close();

            }

           

            std::cout << "\n[JSON Saved] " << payload.substr(0, 80) << "...\n";

        }

    });

    // -----------------------

    // -----------------------

    // 5. The Capture Loop (Main Thread)

    capture.startCapture([&](const RawPacket& raw) {

        if (!g_running) {

            capture.stop();

            return;

        }



        auto now = std::chrono::steady_clock::now();

        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_report_time).count() >= 10) {

            last_report_time = now;

            std::cout << fp_manager.generateClassificationReport();

        }



        // Create the job and assign a safe ID

        DPI::PacketJob job;

        job.packet_id = ++global_packet_id;

        job.data = raw.data;

        job.ts_sec = raw.header.ts_sec;

        job.ts_usec = raw.header.ts_usec;



        // ZERO OUT the tuple to prevent memory garbage crashes!

        job.tuple.src_ip = 0;

        job.tuple.dst_ip = 0;

        job.tuple.src_port = 0;

        job.tuple.dst_port = 0;

        job.tuple.protocol = 0;



        // Shallow Parse: Extract the 5-Tuple so the Load Balancer can route it safely

        ParsedPacket parsed;

        if (PacketParser::parse(raw, parsed)) {

            if (parsed.has_tcp) {

                job.tuple.src_ip = inet_addr(parsed.src_ip.c_str());

                job.tuple.dst_ip = inet_addr(parsed.dest_ip.c_str());

                job.tuple.src_port = parsed.src_port;

                job.tuple.dst_port = parsed.dest_port;

                job.tuple.protocol = 6; // TCP

               

                // Pass the payload info if your Fast Path needs it

                job.payload_length = parsed.payload_length;

                if (parsed.payload_data != nullptr) {

                    job.payload_offset = parsed.payload_data - raw.data.data();

                }

            }

        }



        // Safely push the clean job to the Load Balancer

        load_balancer.getInputQueue().push(job);

    });



    // 7. Clean Shutdown

    std::cout << "\n[Shutdown] Stopping threads safely...\n";

    load_balancer.stop();

    fp_manager.stopAll();

   

// --- ADD THIS ---

    if (json_broadcaster.joinable()) {

        json_broadcaster.join();

    }

    // --------------

    std::cout << "Analysis Complete.\n";

    return 0;

}

// ─────────────────────────────────────────────────────────────

// Entry point

// ───────────────────────────────────────────────────────────── 



int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    std::cout << "====================================\n";
    std::cout << "     Packet Analyzer v2.0\n";
    std::cout << "====================================\n\n";

    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    std::string mode = argv[1];

    // ── List interfaces ──────────────────────────────────────
    if (mode == "--list-interfaces") {
        LiveCapture::listInterfaces();
        return 0;
    }

    // ── File mode ────────────────────────────────────────────
    if (mode == "--file") {
        if (argc < 3) {
            std::cerr << "Error: --file requires a filename.\n";
            printUsage(argv[0]);
            return 1;
        }
        std::string filename  = argv[2];
        int         max_pkts  = (argc >= 4) ? std::stoi(argv[3]) : -1;
        return runFileMode(filename, max_pkts);
    }

    // ── Live mode ────────────────────────────────────────────
    if (mode == "--live") {
        if (argc < 3) {
            std::cerr << "Error: --live requires an interface name.\n";
            std::cerr << "Run with --list-interfaces to see available interfaces.\n";
            return 1;
        }
        std::string iface    = argv[2];
        int         max_pkts = (argc >= 4) ? std::stoi(argv[3]) : -1;
        return runLiveMode(iface, max_pkts);
    }
    // ── Multi-Threaded Live mode ──────────────────────────────
    if (mode == "--live-mt") {
        if (argc < 3) {
            std::cerr << "Error: --live-mt requires an interface name.\n";
            return 1;
        }
        std::string iface = argv[2];
        int num_threads = 4; // Default to 4 Fast Path workers
        
        // Check if user specified thread count
        if (argc >= 4) {
            try { num_threads = std::stoi(argv[3]); } catch(...) {}
        }
        
        // We will write this function below!
        return runLiveModeMT(iface, num_threads); 
    }

    // ── Legacy: old-style usage (just a filename, no flag) ───
    // keeps backward compatibility if someone runs: packet_analyzer capture.pcap
    if (mode[0] != '-') {
        std::string filename = argv[1];
        int         max_pkts = (argc >= 3) ? std::stoi(argv[2]) : -1;
        return runFileMode(filename, max_pkts);
    }

    std::cerr << "Error: Unknown option '" << mode << "'\n";
    printUsage(argv[0]);
    return 1;
}