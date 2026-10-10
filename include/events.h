#ifndef DPI_EVENTS_H
#define DPI_EVENTS_H

#include <string>
#include <vector>
#include <mutex>
#include <functional>
#include <fstream>
#include <atomic>
#include <memory>
#include "types.h"

namespace DPI {

class IPCEmitter;

// Event types
enum class AnomalyType {
    PORT_SCAN,
    SYN_FLOOD,
    DNS_TUNNEL
};

std::string anomalyTypeToString(AnomalyType type);

// Event structures
struct AnomalyEvent {
    double timestamp;  // Unix timestamp (sec + usec/1e6)
    AnomalyType type;
    std::string src_ip;
    std::string target_ip;
    uint32_t count = 0;
    std::string detail;

    std::string toJSON() const;
};

struct SecurityAlert {
    double timestamp;
    std::string alert_type;  // "MALICIOUS", "PORT_SCAN", "SYN_FLOOD", "DNS_TUNNEL", "VPN_DETECTED"
    FiveTuple tuple;
    std::string app_or_domain;
    bool blocked;
    std::string reason;
    std::string detail;

    std::string toJSON() const;
};

struct SecurityStats {
    std::atomic<uint64_t> port_scan_alerts{0};
    std::atomic<uint64_t> syn_flood_alerts{0};
    std::atomic<uint64_t> dns_tunnel_alerts{0};
    std::atomic<uint64_t> malicious_domain_blocks{0};
    std::atomic<uint64_t> vpn_detections{0};
    std::atomic<uint64_t> vpn_blocks{0};

    SecurityStats() = default;
    SecurityStats(const SecurityStats&) = delete;
    SecurityStats& operator=(const SecurityStats&) = delete;

    std::string toJSON(uint64_t total_packets, uint64_t total_bytes, uint64_t total_blocked) const;
};

// Thread-safe Event Sink to publish alerts and JSON streams
class EventSink {
public:
    static EventSink& instance();

    using EventCallback = std::function<void(const std::string&)>;

    void setCallback(EventCallback cb);
    bool openFile(const std::string& filepath);
    void closeFile();

    void emitAnomaly(const AnomalyEvent& event);
    void emitAlert(const SecurityAlert& alert);
    void emitRawJSON(const std::string& json);

    // Connect the event sink to the engine's live telemetry channels.
    void configureTelemetry(IPCEmitter* ipc_emitter, DPIStats* engine_stats);

    SecurityStats& getStats() { return stats_; }
    const SecurityStats& getStats() const { return stats_; }

    void setConsoleAlerts(bool enable) { console_alerts_.store(enable); }
    bool consoleAlertsEnabled() const { return console_alerts_.load(); }

private:
    EventSink() = default;
    ~EventSink();

    std::mutex mutex_;
    EventCallback callback_;
    std::ofstream outfile_;
    SecurityStats stats_;
    IPCEmitter* ipc_emitter_ = nullptr;
    DPIStats* engine_stats_ = nullptr;
    std::atomic<bool> console_alerts_{true};
};

} // namespace DPI

#endif // DPI_EVENTS_H
