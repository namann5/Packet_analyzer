#include "ipc_emitter.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstring>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
#endif

namespace DPI {

#ifdef _WIN32
std::atomic<int> IPCEmitter::wsa_init_count_{0};

void IPCEmitter::initWSA() {
    if (wsa_init_count_++ == 0) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
    }
}

void IPCEmitter::cleanupWSA() {
    if (--wsa_init_count_ == 0) {
        WSACleanup();
    }
}
#endif

IPCEmitter::IPCEmitter() {
#ifdef _WIN32
    initWSA();
#endif
}

IPCEmitter::~IPCEmitter() {
    disconnect();
#ifdef _WIN32
    cleanupWSA();
#endif
}

bool IPCEmitter::connect(const std::string& host, uint16_t port) {
    std::lock_guard<std::mutex> lock(socket_mutex_);
    host_ = host;
    port_ = port;

    if (connected_) {
        return true;
    }

#ifdef _WIN32
    SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        return false;
    }
    sock_ = static_cast<uintptr_t>(s);
#else
    int s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        return false;
    }
    sock_ = s;
#endif

    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);

    if (inet_pton(AF_INET, host_.c_str(), &addr.sin_addr) <= 0) {
        disconnect();
        return false;
    }

    if (::connect(static_cast<
#ifdef _WIN32
        SOCKET
#else
        int
#endif
    >(sock_), reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        disconnect();
        return false;
    }

    connected_ = true;
    return true;
}

void IPCEmitter::disconnect() {
    std::lock_guard<std::mutex> lock(socket_mutex_);
#ifdef _WIN32
    if (sock_ != ~0ULL) {
        ::closesocket(static_cast<SOCKET>(sock_));
        sock_ = ~0ULL;
    }
#else
    if (sock_ >= 0) {
        ::close(sock_);
        sock_ = -1;
    }
#endif
    connected_ = false;
}

bool IPCEmitter::sendRawJson(const std::string& json_str) {
    if (!connected_) {
        // Attempt quick connect
        if (!connect(host_, port_)) {
            return false;
        }
    }

    std::string line = json_str + "\n";
    std::lock_guard<std::mutex> lock(socket_mutex_);

    if (!connected_) {
        return false;
    }

    int bytes_sent = ::send(
        static_cast<
#ifdef _WIN32
            SOCKET
#else
            int
#endif
        >(sock_),
        line.c_str(),
        static_cast<int>(line.size()),
        0
    );

    if (bytes_sent <= 0) {
#ifdef _WIN32
        ::closesocket(static_cast<SOCKET>(sock_));
        sock_ = ~0ULL;
#else
        ::close(sock_);
        sock_ = -1;
#endif
        connected_ = false;
        return false;
    }

    return true;
}

void IPCEmitter::emitAppClassified(const FiveTuple& tuple,
                                   const std::string& app,
                                   bool blocked,
                                   const std::string& reason,
                                   size_t packet_bytes) {
    double ts = std::chrono::duration<double>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    std::ostringstream ss;
    ss << "{\"event\":\"app_classified\","
       << "\"ts\":" << std::fixed << std::setprecision(3) << ts << ","
       << "\"five_tuple\":{"
       << "\"src_ip\":\"" << formatIP(tuple.src_ip) << "\","
       << "\"src_port\":" << tuple.src_port << ","
       << "\"dst_ip\":\"" << formatIP(tuple.dst_ip) << "\","
       << "\"dst_port\":" << tuple.dst_port << ","
       << "\"proto\":\"" << (tuple.protocol == 6 ? "TCP" : (tuple.protocol == 17 ? "UDP" : "OTHER")) << "\""
       << "},"
       << "\"app\":\"" << (app.empty() ? "Unknown" : app) << "\","
       << "\"bytes\":" << packet_bytes << ","
       << "\"blocked\":" << (blocked ? "true" : "false") << ","
       << "\"reason\":" << (reason.empty() ? "null" : ("\"" + reason + "\""))
       << "}";

    sendRawJson(ss.str());
}

void IPCEmitter::emitAnomaly(const std::string& type,
                             const std::string& src_ip,
                             const std::string& target_ip,
                             int ports_seen) {
    double ts = std::chrono::duration<double>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    std::ostringstream ss;
    ss << "{\"event\":\"anomaly\","
       << "\"ts\":" << std::fixed << std::setprecision(3) << ts << ","
       << "\"type\":\"" << type << "\","
       << "\"detail\":{"
       << "\"src_ip\":\"" << src_ip << "\","
       << "\"target\":\"" << target_ip << "\","
       << "\"ports_seen\":" << ports_seen
       << "}}";

    sendRawJson(ss.str());
}

void IPCEmitter::emitStats(const DPIStats& stats, double throughput_bps) {
    double ts = std::chrono::duration<double>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    std::ostringstream ss;
    ss << "{\"event\":\"stats\","
       << "\"ts\":" << std::fixed << std::setprecision(1) << ts << ","
       << "\"total_packets\":" << stats.total_packets.load() << ","
       << "\"total_bytes\":" << stats.total_bytes.load() << ","
       << "\"throughput_bps\":" << std::fixed << std::setprecision(2) << throughput_bps << ","
       << "\"app_breakdown\":{";

    bool first = true;
    for (size_t i = 0; i < static_cast<size_t>(AppType::APP_COUNT); ++i) {
        uint64_t count = stats.app_counts[i].load();
        if (count > 0) {
            if (!first) ss << ",";
            ss << "\"" << appTypeToString(static_cast<AppType>(i)) << "\":" << count;
            first = false;
        }
    }
    if (first) {
        ss << "\"Unknown\":0";
    }
    ss << "},"
       << "\"blocked_total\":" << stats.blocked_total.load() << ","
       << "\"blocked_reasons\":{"
       << "\"IP\":" << stats.blocked_by_ip.load() << ","
       << "\"PORT\":" << stats.blocked_by_port.load() << ","
       << "\"APP\":" << stats.blocked_by_app.load() << ","
       << "\"DOMAIN\":" << stats.blocked_by_domain.load() << ","
       << "\"MALICIOUS\":" << stats.blocked_by_malicious.load() << ","
       << "\"VPN_DETECTED\":" << stats.blocked_by_vpn.load()
       << "},"
       << "\"scan_alerts\":" << stats.scan_alerts.load() << ","
       << "\"syn_flood_alerts\":" << stats.syn_flood_alerts.load() << ","
       << "\"dns_tunnel_alerts\":" << stats.dns_tunnel_alerts.load()
       << "}";

    sendRawJson(ss.str());
}

} // namespace DPI
