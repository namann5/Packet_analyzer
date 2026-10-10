#include "events.h"
#include "ipc_emitter.h"
#include <algorithm>
#include <iostream>
#include <limits>
#include <sstream>
#include <iomanip>

namespace DPI {

namespace {

std::string escapeJSON(const std::string& input) {
    static const char* hexd = "0123456789abcdef";
    const unsigned char* s = reinterpret_cast<const unsigned char*>(input.data());
    const size_t n = input.size();

    std::string out;
    out.reserve(n);

    size_t i = 0;
    while (i < n) {
        unsigned char c = s[i];
        if (c == '"')       { out += "\\\""; ++i; }
        else if (c == '\\') { out += "\\\\"; ++i; }
        else if (c == '\b') { out += "\\b";  ++i; }
        else if (c == '\f') { out += "\\f";  ++i; }
        else if (c == '\n') { out += "\\n";  ++i; }
        else if (c == '\r') { out += "\\r";  ++i; }
        else if (c == '\t') { out += "\\t";  ++i; }
        else if (c < 0x20) {
            out += "\\u00";
            out += hexd[(c >> 4) & 0xF];
            out += hexd[c & 0xF];
            ++i;
        } else if (c < 0x80) {
            out += static_cast<char>(c);
            ++i;
        } else {
            // Validate a UTF-8 multi-byte sequence; escape invalid/lone bytes
            // so malformed input still yields valid JSON.
            int len = 0;
            if ((c & 0xE0) == 0xC0) len = 2;
            else if ((c & 0xF0) == 0xE0) len = 3;
            else if ((c & 0xF8) == 0xF0) len = 4;

            bool valid = (len > 0) && (i + static_cast<size_t>(len) <= n);
            if (valid) {
                for (int k = 1; k < len; ++k) {
                    if ((s[i + k] & 0xC0) != 0x80) { valid = false; break; }
                }
                if (valid && len == 2 && c < 0xC2) valid = false;                 // overlong
                if (valid && len == 3 && c == 0xE0 && s[i + 1] < 0xA0) valid = false;
                if (valid && len == 3 && c == 0xED && s[i + 1] >= 0xA0) valid = false;
                if (valid && len == 4 && c == 0xF0 && s[i + 1] < 0x90) valid = false;
                if (valid && len == 4 && c == 0xF4 && s[i + 1] >= 0x90) valid = false;
            }

            if (valid) {
                out.append(reinterpret_cast<const char*>(s + i), static_cast<size_t>(len));
                i += static_cast<size_t>(len);
            } else {
                out += "\\u00";
                out += hexd[(c >> 4) & 0xF];
                out += hexd[c & 0xF];
                ++i;
            }
        }
    }
    return out;
}

// Replace terminal control characters so untrusted fields cannot inject
// escape sequences into the console.
std::string sanitizeForConsole(const std::string& input) {
    std::string out;
    out.reserve(input.size());
    for (unsigned char c : input) {
        if (c < 0x20 || c == 0x7F) {
            out += '?';
        } else {
            out += static_cast<char>(c);
        }
    }
    return out;
}

std::string ipToStr(uint32_t ip) {
    std::ostringstream ss;
    ss << ((ip >> 0) & 0xFF) << "."
       << ((ip >> 8) & 0xFF) << "."
       << ((ip >> 16) & 0xFF) << "."
       << ((ip >> 24) & 0xFF);
    return ss.str();
}

} // namespace

std::string anomalyTypeToString(AnomalyType type) {
    switch (type) {
        case AnomalyType::PORT_SCAN: return "PORT_SCAN";
        case AnomalyType::SYN_FLOOD: return "SYN_FLOOD";
        case AnomalyType::DNS_TUNNEL: return "DNS_TUNNEL";
        default: return "UNKNOWN";
    }
}

std::string AnomalyEvent::toJSON() const {
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(3);
    ss << "{\"event\":\"anomaly\","
       << "\"ts\":" << timestamp << ","
       << "\"type\":\"" << anomalyTypeToString(type) << "\","
       << "\"detail\":{"
       << "\"src_ip\":\"" << escapeJSON(src_ip) << "\","
       << "\"target\":\"" << escapeJSON(target_ip) << "\","
       << "\"count\":" << count << ","
       << "\"info\":\"" << escapeJSON(detail) << "\"}"
       << "}";
    return ss.str();
}

std::string SecurityAlert::toJSON() const {
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(3);
    ss << "{\"event\":\"security_alert\","
       << "\"ts\":" << timestamp << ","
       << "\"alert_type\":\"" << escapeJSON(alert_type) << "\","
       << "\"five_tuple\":{"
       << "\"src_ip\":\"" << ipToStr(tuple.src_ip) << "\","
       << "\"src_port\":" << tuple.src_port << ","
       << "\"dst_ip\":\"" << ipToStr(tuple.dst_ip) << "\","
       << "\"dst_port\":" << tuple.dst_port << ","
       << "\"proto\":\"" << (tuple.protocol == 6 ? "TCP" : tuple.protocol == 17 ? "UDP" : std::to_string(tuple.protocol)) << "\"},"
       << "\"app_or_domain\":\"" << escapeJSON(app_or_domain) << "\","
       << "\"blocked\":" << (blocked ? "true" : "false") << ","
       << "\"reason\":\"" << escapeJSON(reason) << "\","
       << "\"detail\":\"" << escapeJSON(detail) << "\""
       << "}";
    return ss.str();
}

std::string SecurityStats::toJSON(uint64_t total_packets, uint64_t total_bytes, uint64_t total_blocked) const {
    std::ostringstream ss;
    ss << "{"
       << "\"total_packets\":" << total_packets << ","
       << "\"total_bytes\":" << total_bytes << ","
       << "\"blocked_total\":" << total_blocked << ","
       << "\"scan_alerts\":" << port_scan_alerts.load() << ","
       << "\"syn_flood_alerts\":" << syn_flood_alerts.load() << ","
       << "\"dns_tunnel_alerts\":" << dns_tunnel_alerts.load() << ","
       << "\"malicious_domain_blocks\":" << malicious_domain_blocks.load() << ","
       << "\"vpn_detections\":" << vpn_detections.load() << ","
       << "\"vpn_blocks\":" << vpn_blocks.load()
       << "}";
    return ss.str();
}

EventSink& EventSink::instance() {
    static EventSink s_instance;
    return s_instance;
}

EventSink::~EventSink() {
    closeFile();
}

void EventSink::setCallback(EventCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = std::move(cb);
}

bool EventSink::openFile(const std::string& filepath) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (outfile_.is_open()) {
        outfile_.close();
    }
    outfile_.open(filepath, std::ios::out | std::ios::app);
    return outfile_.is_open();
}

void EventSink::closeFile() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (outfile_.is_open()) {
        outfile_.close();
    }
}

void EventSink::configureTelemetry(IPCEmitter* ipc_emitter, DPIStats* engine_stats) {
    std::lock_guard<std::mutex> lock(mutex_);
    ipc_emitter_ = ipc_emitter;
    engine_stats_ = engine_stats;
}

void EventSink::emitAnomaly(const AnomalyEvent& event) {
    switch (event.type) {
        case AnomalyType::PORT_SCAN:
            stats_.port_scan_alerts++;
            break;
        case AnomalyType::SYN_FLOOD:
            stats_.syn_flood_alerts++;
            break;
        case AnomalyType::DNS_TUNNEL:
            stats_.dns_tunnel_alerts++;
            break;
    }

    IPCEmitter* ipc_emitter = nullptr;
    DPIStats* engine_stats = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ipc_emitter = ipc_emitter_;
        engine_stats = engine_stats_;
    }

    if (engine_stats) {
        switch (event.type) {
            case AnomalyType::PORT_SCAN:
                engine_stats->scan_alerts++;
                break;
            case AnomalyType::SYN_FLOOD:
                engine_stats->syn_flood_alerts++;
                break;
            case AnomalyType::DNS_TUNNEL:
                engine_stats->dns_tunnel_alerts++;
                break;
        }
    }

    if (ipc_emitter) {
        const auto ports_seen = static_cast<int>(std::min<uint32_t>(
            event.count, static_cast<uint32_t>(std::numeric_limits<int>::max())));
        ipc_emitter->emitAnomaly(
            anomalyTypeToString(event.type), event.src_ip, event.target_ip, ports_seen);
    }

    std::string json = event.toJSON();
    emitRawJSON(json);

    if (console_alerts_.load()) {
        std::cout << "\033[1;31m[ALERT] " << anomalyTypeToString(event.type)
                  << " detected from " << sanitizeForConsole(event.src_ip)
                  << " -> " << sanitizeForConsole(event.target_ip)
                  << " (" << sanitizeForConsole(event.detail) << ")\033[0m\n";
    }
}

void EventSink::emitAlert(const SecurityAlert& alert) {
    if (alert.reason == "MALICIOUS") {
        stats_.malicious_domain_blocks++;
    } else if (alert.reason == "VPN_DETECTED") {
        stats_.vpn_detections++;
        if (alert.blocked) {
            stats_.vpn_blocks++;
        }
    }

    IPCEmitter* ipc_emitter = nullptr;
    DPIStats* engine_stats = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ipc_emitter = ipc_emitter_;
        engine_stats = engine_stats_;
    }

    if (engine_stats && alert.blocked) {
        engine_stats->blocked_total++;
    }

    std::string json = alert.toJSON();
    emitRawJSON(json);

    // The dashboard connection list is populated by app_classified frames.
    // Mirror blocked security alerts into that schema so malicious-domain and
    // VPN blocks appear in /api/blocked as well as aggregate counters.
    if (ipc_emitter && alert.blocked) {
        ipc_emitter->emitAppClassified(
            alert.tuple, alert.app_or_domain, true, alert.reason);
    }

    if (console_alerts_.load()) {
        std::string color = alert.blocked ? "\033[1;31m" : "\033[1;33m";
        std::cout << color << "[SECURITY] " << sanitizeForConsole(alert.alert_type)
                  << (alert.blocked ? " [BLOCKED]" : " [FLAGGED]")
                  << " " << sanitizeForConsole(alert.app_or_domain)
                  << " (" << sanitizeForConsole(alert.detail) << ")\033[0m\n";
    }
}

void EventSink::emitRawJSON(const std::string& json) {
    EventCallback cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (outfile_.is_open()) {
            outfile_ << json << "\n";
            outfile_.flush();
        }
        // Copy the callback so it is invoked without holding the lock; a
        // callback that re-enters EventSink would otherwise deadlock.
        cb = callback_;
    }
    if (cb) {
        cb(json);
    }
}

} // namespace DPI
