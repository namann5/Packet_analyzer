#ifndef DPI_ANOMALY_DETECTOR_H
#define DPI_ANOMALY_DETECTOR_H

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <list>
#include <mutex>
#include <chrono>
#include <optional>
#include "types.h"
#include "events.h"

namespace DPI {

class AnomalyDetector {
public:
    struct Config {
        // Port scan config
        double port_scan_window_sec = 5.0;
        size_t port_scan_threshold = 15;        // > 15 distinct ports to one target
        size_t port_scan_max_entries = 10000;   // LRU cap
        double port_scan_alert_cooldown = 5.0;

        // SYN flood config
        double syn_flood_window_sec = 1.0;
        size_t syn_flood_threshold = 500;       // > 500 SYN/s
        size_t syn_flood_max_entries = 10000;
        double syn_flood_alert_cooldown = 2.0;

        // DNS tunneling config
        size_t dns_tunnel_min_depth = 4;
        size_t dns_tunnel_min_label_len = 20;
        double dns_tunnel_min_entropy = 4.0;
        double dns_tunnel_cooldown = 10.0;
        size_t dns_tunnel_max_entries = 10000;  // LRU/state cap

        // Auto-blocking
        bool auto_block_port_scans = true;
        bool auto_block_syn_floods = true;
    };

    AnomalyDetector();
    explicit AnomalyDetector(const Config& config);

    // Process a packet for port scan and SYN flood detection
    // Returns true if packet is part of an anomaly that should be dropped
    bool processPacket(const PacketJob& job);

    // Check a DNS query for tunneling heuristics
    // Returns true if DNS tunneling detected
    bool inspectDNSQuery(const PacketJob& job, const std::string& query);

    // Helpers exposed for unit testing
    static double calculateShannonEntropy(const std::string& str);
    static std::vector<std::string> splitDomainLabels(const std::string& domain);
    static size_t calculateDomainDepth(const std::string& domain);

    // Check if an IP is currently marked as an active attacker (auto-blocked)
    bool isIPAutoBlocked(uint32_t ip) const;

    // Reset all detector states
    void reset();

    const Config& getConfig() const { return config_; }
    void setConfig(const Config& config) { config_ = config; }

private:
    Config config_;

    // ========================================================================
    // 6.1 Port Scan Detector structures
    // Key: (src_ip, dst_ip)
    // ========================================================================
    struct PortScanKey {
        uint32_t src_ip;
        uint32_t dst_ip;

        bool operator==(const PortScanKey& o) const {
            return src_ip == o.src_ip && dst_ip == o.dst_ip;
        }
    };

    struct PortScanKeyHash {
        size_t operator()(const PortScanKey& k) const {
            return std::hash<uint32_t>{}(k.src_ip) ^ (std::hash<uint32_t>{}(k.dst_ip) << 1);
        }
    };

    struct PortRecord {
        double timestamp;
        uint16_t port;
    };

    struct PortScanEntry {
        std::vector<PortRecord> records;
        double last_alert_time{0.0};
    };

    using PortScanMap = std::unordered_map<PortScanKey, PortScanEntry, PortScanKeyHash>;
    using PortScanLRUList = std::list<PortScanKey>;

    mutable std::mutex port_scan_mutex_;
    PortScanMap port_scan_map_;
    PortScanLRUList port_scan_lru_;
    std::unordered_map<PortScanKey, PortScanLRUList::iterator, PortScanKeyHash> port_scan_lru_map_;

    bool checkPortScan(uint32_t src_ip, uint32_t dst_ip, uint16_t dst_port, double now_sec);

    // ========================================================================
    // 6.2 SYN Flood Detector structures
    // Key: dst_ip
    // ========================================================================
    struct SYNRecord {
        double timestamp;
    };

    struct SYNFloodEntry {
        std::vector<SYNRecord> syn_records;
        double last_alert_time{0.0};
    };

    using SYNFloodMap = std::unordered_map<uint32_t, SYNFloodEntry>;
    using SYNFloodLRUList = std::list<uint32_t>;

    mutable std::mutex syn_flood_mutex_;
    SYNFloodMap syn_flood_map_;
    SYNFloodLRUList syn_flood_lru_;
    std::unordered_map<uint32_t, SYNFloodLRUList::iterator> syn_flood_lru_map_;

    bool checkSYNFlood(uint32_t dst_ip, double now_sec);

    // ========================================================================
    // 6.3 DNS Tunneling structures
    // Key: (src_ip, tunnel_root_pattern)
    // ========================================================================
    struct DNSTunnelKey {
        uint32_t src_ip;
        std::string pattern;

        bool operator==(const DNSTunnelKey& o) const {
            return src_ip == o.src_ip && pattern == o.pattern;
        }
    };

    struct DNSTunnelKeyHash {
        size_t operator()(const DNSTunnelKey& k) const {
            return std::hash<uint32_t>{}(k.src_ip) ^ (std::hash<std::string>{}(k.pattern) << 1);
        }
    };

    mutable std::mutex dns_tunnel_mutex_;
    std::unordered_map<DNSTunnelKey, double, DNSTunnelKeyHash> dns_tunnel_seen_;
    std::unordered_set<std::string> unique_tunnel_domains_;

    // ========================================================================
    // Auto-blocked IPs from anomaly triggers
    // ========================================================================
    mutable std::mutex blocked_ips_mutex_;
    std::unordered_set<uint32_t> auto_blocked_ips_;

    // Time helper
    static double packetTimeSec(const PacketJob& job);
};

} // namespace DPI

#endif // DPI_ANOMALY_DETECTOR_H
