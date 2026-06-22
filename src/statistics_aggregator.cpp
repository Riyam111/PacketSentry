#include "statistics_aggregator.h"
#include <json.hpp>

using json = nlohmann::json;

namespace DPI {

StatisticsAggregator::StatisticsAggregator(int num_workers) {
    for (int i = 0; i < num_workers; ++i) {
        workers_[i] = new WorkerStats{i};
    }
}

StatisticsAggregator::~StatisticsAggregator() {
    for (auto& pair : apps_) delete pair.second;
    for (auto& pair : domains_) delete pair.second;
    for (auto& pair : workers_) delete pair.second;
}

void StatisticsAggregator::recordWorkerMetric(int worker_id, uint64_t packets, uint64_t bytes, int queue_len) {
    if (workers_.count(worker_id)) {
        workers_[worker_id]->packets_processed += packets;
        workers_[worker_id]->current_queue_length = queue_len;
        system_.total_packets += packets;
        system_.total_bytes += bytes;
    }
}

void StatisticsAggregator::recordNewConnection() {
    system_.total_connections++;
    system_.active_connections++;
    system_.unknown_connections++;
}

void StatisticsAggregator::recordClosedConnection() {
    if (system_.active_connections > 0) {
        system_.active_connections--;
    }
}

void StatisticsAggregator::recordClassification(const std::string& domain, const std::string& app, const std::string& src_ip, const std::string& dst_ip) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    // Move from Unknown to Classified
    if (system_.unknown_connections > 0) system_.unknown_connections--;
    system_.classified_connections++;
    workers_[0]->classifications++; // Track global classifications

    // Track Application
    if (apps_.find(app) == apps_.end()) {
        apps_[app] = new AppStats{app};
    }
    apps_[app]->connections++;

    // Track Specific Domain
    if (domains_.find(domain) == domains_.end()) {
        domains_[domain] = new DomainStats{domain, app};
    }
    domains_[domain]->connections++;

    // Log the recent flow event for the dashboard terminal
    FlowEvent event{
        static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()),
        domain, app, src_ip, dst_ip
    };
    
    if (recent_flows_.size() < 50) {
        recent_flows_.push_back(event);
    } else {
        recent_flows_[flow_index_] = event;
        flow_index_ = (flow_index_ + 1) % 50;
    }
}
void StatisticsAggregator::recordAppTraffic(const std::string& app, const std::string& domain, uint64_t bytes) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    // Add packets and bytes to the Application
    if (apps_.find(app) != apps_.end()) {
        apps_[app]->packets++;
        apps_[app]->bytes += bytes;
    }
    
    // Add packets and bytes to the Specific Domain
    if (!domain.empty() && domains_.find(domain) != domains_.end()) {
        domains_[domain]->packets++;
        domains_[domain]->bytes += bytes;
    }
}

std::string StatisticsAggregator::generateDashboardJSON() {
    json j;
    
    // 1. System Metrics
    j["system"]["active_connections"] = system_.active_connections.load();
    j["system"]["total_connections"] = system_.total_connections.load();
    j["system"]["classified_connections"] = system_.classified_connections.load();
    j["system"]["unknown_connections"] = system_.unknown_connections.load();
    j["system"]["total_packets"] = system_.total_packets.load();
    j["system"]["total_bytes"] = system_.total_bytes.load();
    
    uint64_t total_conn = system_.total_connections.load();
    j["system"]["classification_rate"] = (total_conn > 0) ? 
        (100.0 * system_.classified_connections.load() / total_conn) : 0.0;

    // 2. Apps, Domains, and Recent Flows (Mutex Locked)
    json apps_array = json::array();
    json domains_array = json::array();
    json flows_array = json::array();
    
    {
        std::lock_guard<std::mutex> lock(data_mutex_);
        
        for (const auto& [name, stats] : apps_) {
            json app_json;
            app_json["name"] = name;
            app_json["connections"] = stats->connections.load();
            app_json["packets"] = stats->packets.load();
            app_json["bytes"] = stats->bytes.load();
            app_json["traffic_percent"] = (total_conn > 0) ? (100.0 * stats->connections.load() / total_conn) : 0.0;
            apps_array.push_back(app_json);
        }

        for (const auto& [name, stats] : domains_) {
            json dom_json;
            dom_json["domain"] = name;
            dom_json["application"] = stats->app_name;
            dom_json["connections"] = stats->connections.load();
            domains_array.push_back(dom_json);
        }

        for (size_t i = 0; i < recent_flows_.size(); ++i) {
            size_t idx = (flow_index_ + i) % recent_flows_.size();
            json flow_json;
            flow_json["timestamp"] = recent_flows_[idx].timestamp;
            flow_json["domain"] = recent_flows_[idx].domain;
            flow_json["application"] = recent_flows_[idx].app;
            flow_json["src_ip"] = recent_flows_[idx].src_ip;
            flow_json["dst_ip"] = recent_flows_[idx].dst_ip;
            flows_array.push_back(flow_json);
        }
    }
    
    j["applications"] = apps_array;
    j["domains"] = domains_array;
    j["recent_flows"] = flows_array;

    // 3. Worker Thread Metrics
    json workers_array = json::array();
    for (const auto& [id, stats] : workers_) {
        json w_json;
        w_json["id"] = id;
        w_json["packets_processed"] = stats->packets_processed.load();
        w_json["classifications"] = stats->classifications.load();
        w_json["queue_length"] = stats->current_queue_length.load();
        workers_array.push_back(w_json);
    }
    j["workers"] = workers_array;

    return j.dump();
}

} // namespace DPI