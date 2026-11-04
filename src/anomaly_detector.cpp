#include "anomaly_detector.h"
#include "events.h"
#include "packet_parser.h"
#include <cmath>
#include <sstream>
#include <iomanip>
#include <unordered_map>
#include <set>
#include <algorithm>
#include <limits>

namespace DPI {

namespace {

std::string ipToString(uint32_t ip) {
    std::ostringstream ss;
    ss << ((ip >> 0) & 0xFF) << "."
       << ((ip >> 8) & 0xFF) << "."
       << ((ip >> 16) & 0xFF) << "."
       << ((ip >> 24) & 0xFF);
    return ss.str();
}

} // namespace

AnomalyDetector::AnomalyDetector() : AnomalyDetector(Config()) {
}

AnomalyDetector::AnomalyDetector(const Config& config)
    : config_(config) {
}

std::string registrableDomain(const std::vector<std::string>& labels) {
    if (labels.size() < 2) return labels.empty() ? std::string() : labels.front();
    static const std::unordered_set<std::string> compound_suffixes = {
        "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.jp"
    };
    const std::string suffix = labels[labels.size() - 2] + "." + labels.back();
    if (compound_suffixes.find(suffix) != compound_suffixes.end() && labels.size() >= 3) {
        return labels[labels.size() - 3] + "." + suffix;
    }
    return suffix;
}

AnomalyDetector::Config AnomalyDetector::getConfig() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return config_;
}

void AnomalyDetector::setConfig(const Config& config) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    config_ = config;
}

double AnomalyDetector::packetTimeSec(const PacketJob& job) {
    if (!job.timestamp_valid && job.ts_sec == 0 && job.ts_usec == 0) {
        // A zero capture timestamp means the packet was not timestamped.
        // Event timestamps are Unix time, so use the system clock here rather
        // than exposing an unrelated monotonic uptime value.
        auto now = std::chrono::system_clock::now().time_since_epoch();
        return std::chrono::duration<double>(now).count();
    }
    return static_cast<double>(job.ts_sec) + static_cast<double>(job.ts_usec) / 1000000.0;
}

double AnomalyDetector::calculateShannonEntropy(const std::string& str) {
    if (str.empty()) return 0.0;

    std::unordered_map<char, size_t> freqs;
    for (char c : str) {
        freqs[c]++;
    }

    double entropy = 0.0;
    double len = static_cast<double>(str.length());

    for (const auto& kv : freqs) {
        double p = static_cast<double>(kv.second) / len;
        if (p > 0.0) {
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

std::vector<std::string> AnomalyDetector::splitDomainLabels(const std::string& domain) {
    std::vector<std::string> labels;
    if (domain.empty()) return labels;

    size_t start = 0;
    while (start < domain.length()) {
        size_t dot = domain.find('.', start);
        if (dot == std::string::npos) {
            if (start < domain.length()) {
                labels.push_back(domain.substr(start));
            }
            break;
        }
        if (dot > start) {
            labels.push_back(domain.substr(start, dot - start));
        }
        start = dot + 1;
    }

    return labels;
}

size_t AnomalyDetector::calculateDomainDepth(const std::string& domain) {
    auto labels = splitDomainLabels(domain);
    return labels.empty() ? 0 : labels.size() - 1;
}

bool AnomalyDetector::isIPAutoBlocked(uint32_t ip) const {
    std::lock_guard<std::mutex> lock(blocked_ips_mutex_);
    return auto_blocked_ips_.find(ip) != auto_blocked_ips_.end();
}

void AnomalyDetector::reset() {
    {
        std::lock_guard<std::mutex> lock(port_scan_mutex_);
        port_scan_map_.clear();
        port_scan_lru_.clear();
        port_scan_lru_map_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(syn_flood_mutex_);
        syn_flood_map_.clear();
        syn_flood_lru_.clear();
        syn_flood_lru_map_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(dns_tunnel_mutex_);
        dns_tunnel_seen_.clear();
        dns_tunnel_lru_.clear();
        dns_tunnel_lru_map_.clear();
        unique_tunnel_domains_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(blocked_ips_mutex_);
        auto_blocked_ips_.clear();
    }
}

bool AnomalyDetector::processPacket(const PacketJob& job) {
    // 1. Check if source IP is already blocked
    if (isIPAutoBlocked(job.tuple.src_ip)) {
        return true;
    }

    double now_sec = packetTimeSec(job);

    // 2. Check for SYN flood (SYN set, ACK not set, payload length 0)
    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t ACK = 0x10;
    if (job.tuple.protocol == 6) { // TCP
        bool is_syn_only = (job.tcp_flags & SYN) && !(job.tcp_flags & ACK) && (job.payload_length == 0);
        if (is_syn_only) {
            if (checkSYNFlood(job.tuple.dst_ip, now_sec)) {
                return true;
            }
        }
    }

    // 3. Check for Port Scan (count unique destination ports per (src_ip, dst_ip))
    if (checkPortScan(job.tuple.src_ip, job.tuple.dst_ip, job.tuple.dst_port, now_sec)) {
        return true;
    }

    return false;
}

bool AnomalyDetector::checkPortScan(uint32_t src_ip, uint32_t dst_ip, uint16_t dst_port, double now_sec) {
    const Config config = getConfig();
    std::lock_guard<std::mutex> lock(port_scan_mutex_);

    if (config.port_scan_max_entries == 0 || config.port_scan_threshold == 0) {
        return false;
    }

    PortScanKey key{src_ip, dst_ip};

    // Update LRU tracking
    auto lru_it = port_scan_lru_map_.find(key);
    if (lru_it != port_scan_lru_map_.end()) {
        port_scan_lru_.erase(lru_it->second);
    } else {
        if (port_scan_map_.size() >= config.port_scan_max_entries && !port_scan_lru_.empty()) {
            // Evict oldest
            PortScanKey oldest = port_scan_lru_.back();
            port_scan_lru_.pop_back();
            port_scan_lru_map_.erase(oldest);
            port_scan_map_.erase(oldest);
        }
    }
    port_scan_lru_.push_front(key);
    port_scan_lru_map_[key] = port_scan_lru_.begin();

    PortScanEntry& entry = port_scan_map_[key];

    const double cutoff = now_sec - config.port_scan_window_sec;
    for (auto it = entry.last_seen_ports.begin(); it != entry.last_seen_ports.end();) {
        if (it->second < cutoff) {
            it = entry.last_seen_ports.erase(it);
        } else {
            ++it;
        }
    }
    entry.last_seen_ports[dst_port] = now_sec;

    const size_t unique_count = entry.last_seen_ports.size();
    if (unique_count > config.port_scan_threshold) {
        const bool should_alert = !entry.has_alerted ||
            (now_sec - entry.last_alert_time >= config.port_scan_alert_cooldown);
        if (should_alert) {
            entry.last_alert_time = now_sec;
            entry.has_alerted = true;

            AnomalyEvent event;
            event.timestamp = now_sec;
            event.type = AnomalyType::PORT_SCAN;
            event.src_ip = ipToString(src_ip);
            event.target_ip = ipToString(dst_ip);
            event.count = static_cast<uint32_t>(unique_count);

            std::ostringstream ss;
            ss << unique_count << " distinct destination ports in "
               << std::fixed << std::setprecision(1) << config.port_scan_window_sec << "s window";
            event.detail = ss.str();

            EventSink::instance().emitAnomaly(event);

            if (config.auto_block_port_scans) {
                std::lock_guard<std::mutex> b_lock(blocked_ips_mutex_);
                auto_blocked_ips_.insert(src_ip);
            }
        }
        return config.auto_block_port_scans;
    }

    return false;
}

bool AnomalyDetector::checkSYNFlood(uint32_t dst_ip, double now_sec) {
    const Config config = getConfig();
    std::lock_guard<std::mutex> lock(syn_flood_mutex_);

    if (config.syn_flood_max_entries == 0 || config.syn_flood_threshold == 0) {
        return false;
    }

    // Update LRU tracking
    auto lru_it = syn_flood_lru_map_.find(dst_ip);
    if (lru_it != syn_flood_lru_map_.end()) {
        syn_flood_lru_.erase(lru_it->second);
    } else {
        if (syn_flood_map_.size() >= config.syn_flood_max_entries && !syn_flood_lru_.empty()) {
            uint32_t oldest = syn_flood_lru_.back();
            syn_flood_lru_.pop_back();
            syn_flood_lru_map_.erase(oldest);
            syn_flood_map_.erase(oldest);
        }
    }
    syn_flood_lru_.push_front(dst_ip);
    syn_flood_lru_map_[dst_ip] = syn_flood_lru_.begin();

    SYNFloodEntry& entry = syn_flood_map_[dst_ip];

    const double cutoff = now_sec - config.syn_flood_window_sec;
    while (!entry.syn_records.empty() && entry.syn_records.front() < cutoff) {
        entry.syn_records.pop_front();
    }
    entry.syn_records.push_back(now_sec);

    // Keep a bounded sliding window even when a caller configures a very
    // large rate threshold. The detector only needs threshold+1 samples to
    // prove that the threshold was exceeded.
    const size_t history_cap = config.syn_flood_threshold == std::numeric_limits<size_t>::max()
        ? config.syn_flood_threshold
        : config.syn_flood_threshold + 1;
    while (entry.syn_records.size() > history_cap) {
        entry.syn_records.pop_front();
    }

    size_t count = entry.syn_records.size();
    double window = config.syn_flood_window_sec > 0.0 ? config.syn_flood_window_sec : 1.0;
    double rate = static_cast<double>(count) / window;

    if (rate > static_cast<double>(config.syn_flood_threshold)) {
        bool should_alert = !entry.has_alerted ||
            (now_sec - entry.last_alert_time >= config.syn_flood_alert_cooldown);
        if (should_alert) {
            entry.last_alert_time = now_sec;
            entry.has_alerted = true;

            AnomalyEvent event;
            event.timestamp = now_sec;
            event.type = AnomalyType::SYN_FLOOD;
            event.src_ip = "Multiple";
            event.target_ip = ipToString(dst_ip);
            event.count = static_cast<uint32_t>(count);

            std::ostringstream ss;
            ss << count << " SYN packets (" << std::fixed << std::setprecision(1) << rate
               << " SYN/s) targeting " << ipToString(dst_ip);
            event.detail = ss.str();

            EventSink::instance().emitAnomaly(event);
        }
        return config.auto_block_syn_floods;
    }

    return false;
}

bool AnomalyDetector::inspectDNSQuery(const PacketJob& job, const std::string& query) {
    if (query.empty()) return false;

    const Config config = getConfig();
    if (config.dns_tunnel_max_entries == 0) return false;

    auto labels = splitDomainLabels(query);
    if (labels.size() < 2) return false;

    size_t depth = labels.size() - 1;
    const std::string& leftmost = labels.front();
    double entropy = calculateShannonEntropy(leftmost);

    // Heuristic: depth >= 4 AND (long label ~> 20 chars OR entropy ~> 4.0) -> DNS_TUNNEL
    bool is_tunnel = (depth >= config.dns_tunnel_min_depth) &&
                     (leftmost.length() >= config.dns_tunnel_min_label_len || entropy >= config.dns_tunnel_min_entropy);

    if (!is_tunnel) {
        return false;
    }

    double now_sec = packetTimeSec(job);

    const std::string root_pattern = registrableDomain(labels);

    DNSTunnelKey key{job.tuple.src_ip, root_pattern};

    std::lock_guard<std::mutex> lock(dns_tunnel_mutex_);
    auto it = dns_tunnel_seen_.find(key);
    bool should_alert = (it == dns_tunnel_seen_.end() ||
                         (now_sec - it->second >= config.dns_tunnel_cooldown));

    if (should_alert) {
        dns_tunnel_seen_[key] = now_sec;
        if (it != dns_tunnel_seen_.end()) {
            auto lru_it = dns_tunnel_lru_map_.find(key);
            if (lru_it != dns_tunnel_lru_map_.end()) {
                dns_tunnel_lru_.erase(lru_it->second);
            }
        }
        dns_tunnel_lru_.push_front(key);
        dns_tunnel_lru_map_[key] = dns_tunnel_lru_.begin();
        unique_tunnel_domains_.insert(query);

        while (dns_tunnel_seen_.size() > config.dns_tunnel_max_entries &&
               !dns_tunnel_lru_.empty()) {
            const DNSTunnelKey oldest = dns_tunnel_lru_.back();
            dns_tunnel_lru_.pop_back();
            dns_tunnel_lru_map_.erase(oldest);
            dns_tunnel_seen_.erase(oldest);
        }
        while (unique_tunnel_domains_.size() > config.dns_tunnel_max_entries) {
            unique_tunnel_domains_.erase(unique_tunnel_domains_.begin());
        }

        AnomalyEvent event;
        event.timestamp = now_sec;
        event.type = AnomalyType::DNS_TUNNEL;
        event.src_ip = ipToString(job.tuple.src_ip);
        event.target_ip = ipToString(job.tuple.dst_ip);
        event.count = static_cast<uint32_t>(unique_tunnel_domains_.size());

        std::ostringstream ss;
        ss << "Domain: " << query << " [depth=" << depth
           << ", leftmost_len=" << leftmost.length()
           << ", entropy=" << std::fixed << std::setprecision(2) << entropy << "]";
        event.detail = ss.str();

        EventSink::instance().emitAnomaly(event);
    }

    return true;
}

} // namespace DPI
