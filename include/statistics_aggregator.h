#pragma once

#include <string>
#include <unordered_map>
#include <atomic>
#include <mutex>
#include <vector>
#include <chrono>

namespace DPI {

// Data models with atomic counters for lock-free updates by worker threads
struct SystemStats {
    std::atomic<uint64_t> active_connections{0};
    std::atomic<uint64_t> total_connections{0};
    std::atomic<uint64_t> classified_connections{0};
    std::atomic<uint64_t> unknown_connections{0};
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};
};

struct AppStats {
    std::string app_name;
    std::atomic<uint64_t> connections{0};
    std::atomic<uint64_t> packets{0};
    std::atomic<uint64_t> bytes{0};
};

struct DomainStats {
    std::string domain_name;
    std::string app_name;
    std::atomic<uint64_t> connections{0};
    std::atomic<uint64_t> packets{0};
    std::atomic<uint64_t> bytes{0};
};

struct WorkerStats {
    int worker_id;
    std::atomic<uint64_t> packets_processed{0};
    std::atomic<uint64_t> classifications{0};
    std::atomic<uint64_t> current_queue_length{0}; 
};

struct FlowEvent {
    uint64_t timestamp;
    std::string domain;
    std::string app;
    std::string src_ip;
    std::string dst_ip;
};

class StatisticsAggregator {
private:
    std::mutex data_mutex_;
    
    SystemStats system_;
    std::unordered_map<std::string, AppStats*> apps_;
    std::unordered_map<std::string, DomainStats*> domains_;
    std::unordered_map<int, WorkerStats*> workers_;
    
    // Ring buffer for the last 50 flow events to keep the dashboard snappy
    std::vector<FlowEvent> recent_flows_;
    size_t flow_index_{0};

public:
    StatisticsAggregator(int num_workers);
    ~StatisticsAggregator();

    // 1. Called on every packet
    void recordWorkerMetric(int worker_id, uint64_t packets, uint64_t bytes, int queue_len);

    // 2. Called when a new TCP SYN creates a connection
    void recordNewConnection();

    // 3. Called when a connection is closed (FIN/RST or timeout)
    void recordClosedConnection();

    // 4. Called ONLY when an SNI is found
    void recordClassification(const std::string& domain, const std::string& app, const std::string& src_ip, const std::string& dst_ip);
    void recordAppTraffic(const std::string& app, const std::string& domain, uint64_t bytes);
    std::string generateDashboardJSON();
};

} // namespace DPI