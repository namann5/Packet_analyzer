#ifndef DPI_VPN_DETECTOR_H
#define DPI_VPN_DETECTOR_H

#include <cstdint>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include "types.h"

namespace DPI {

enum class VPNAction {
    FLAG_ONLY = 0,
    BLOCK = 1
};

std::string vpnActionToString(VPNAction action);
VPNAction stringToVPNAction(const std::string& str);

enum class VPNType {
    NONE = 0,
    WIREGUARD,
    OPENVPN,
    IPSEC,
    VPN_IP_RANGE
};

std::string vpnTypeToString(VPNType type);

struct VPNDetectionResult {
    bool detected{false};
    VPNType type{VPNType::NONE};
    std::string protocol_name;
    std::string detail;
};

struct CIDRRange {
    uint32_t network;
    uint32_t mask;
    std::string cidr_str;
    std::string label;

    bool contains(uint32_t ip) const {
        return (ip & mask) == network;
    }
};

class VPNDetector {
public:
    struct Config {
        VPNAction action = VPNAction::FLAG_ONLY; // Default: FLAG_ONLY (alert & monitor, forward packet)
        bool block_vpn = false;                  // Backward compatible flag, synced with action
        std::string vpn_ranges_path = "data/vpn_ranges.json";
    };

    explicit VPNDetector();
    explicit VPNDetector(const Config& config);
    ~VPNDetector();

    // Check packet for VPN protocol fingerprints or known VPN IP ranges
    VPNDetectionResult detect(const PacketJob& job) const;

    // Load known VPN IP ranges from JSON or plaintext file
    bool loadVPNRanges(const std::string& filepath);

    // Add CIDR range programmatically (e.g. "10.8.0.0/24", "OpenVPN Subnet")
    bool addCIDR(const std::string& cidr_str, const std::string& label = "VPN");

    // Fingerprint individual protocols
    static bool isWireGuard(const PacketJob& job, std::string* detail = nullptr);
    static bool isOpenVPN(const PacketJob& job, std::string* detail = nullptr);
    static bool isIPSec(const PacketJob& job, std::string* detail = nullptr);

    bool matchesVPNRange(uint32_t ip, std::string* label = nullptr) const;

    const Config& getConfig() const { return config_; }
    void setConfig(const Config& config) {
        config_ = config;
        if (config_.block_vpn && config_.action != VPNAction::BLOCK) {
            config_.action = VPNAction::BLOCK;
        }
        block_vpn_.store(config_.action == VPNAction::BLOCK);
    }
    void setAction(VPNAction action) {
        config_.action = action;
        config_.block_vpn = (action == VPNAction::BLOCK);
        block_vpn_.store(action == VPNAction::BLOCK);
    }
    VPNAction getAction() const { return config_.action; }
    bool isBlock() const { return config_.action == VPNAction::BLOCK || block_vpn_.load(std::memory_order_relaxed); }
    void setBlockVPN(bool block) {
        config_.block_vpn = block;
        config_.action = block ? VPNAction::BLOCK : VPNAction::FLAG_ONLY;
        block_vpn_.store(block);
    }

    // Thread-safe read of the blocking flag
    bool shouldBlockVPN() const { return isBlock(); }

    size_t getRangeCount() const;

private:
    Config config_;
    std::atomic<bool> block_vpn_{false};
    mutable std::mutex mutex_;
    std::vector<CIDRRange> ranges_;

    static bool parseIPv4(const std::string& ip_str, uint32_t& out);
    static bool parseCIDR(const std::string& cidr_str, uint32_t& network, uint32_t& mask);
};

} // namespace DPI

#endif // DPI_VPN_DETECTOR_H
