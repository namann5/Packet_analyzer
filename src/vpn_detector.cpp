#include "vpn_detector.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace DPI {

std::string vpnTypeToString(VPNType type) {
    switch (type) {
        case VPNType::WIREGUARD:    return "WireGuard";
        case VPNType::OPENVPN:      return "OpenVPN";
        case VPNType::IPSEC:        return "IPSec";
        case VPNType::VPN_IP_RANGE: return "VPN_IP_Range";
        default:                    return "None";
    }
}

VPNDetector::VPNDetector() : VPNDetector(Config()) {
}

VPNDetector::VPNDetector(const Config& config)
    : config_(config) {
    block_vpn_.store(config_.block_vpn);
    if (!config_.vpn_ranges_path.empty()) {
        loadVPNRanges(config_.vpn_ranges_path);
    }
}

VPNDetector::~VPNDetector() = default;

bool VPNDetector::parseIPv4(const std::string& ip_str, uint32_t& out) {
    if (ip_str.empty()) return false;

    uint32_t ip = 0;
    int octet = 0;
    int shift = 0;
    int digits = 0;
    int parts = 0;

    for (char c : ip_str) {
        if (c == '.') {
            if (digits == 0 || parts >= 3) return false;
            ip |= (static_cast<uint32_t>(octet) << shift);
            shift += 8;
            octet = 0;
            digits = 0;
            ++parts;
        } else if (c >= '0' && c <= '9') {
            octet = octet * 10 + (c - '0');
            ++digits;
            if (octet > 255) return false;
        } else {
            return false; // reject any non-digit, non-dot character
        }
    }

    if (digits == 0 || parts != 3) return false;
    ip |= (static_cast<uint32_t>(octet) << shift);
    out = ip;
    return true;
}

bool VPNDetector::parseCIDR(const std::string& cidr_str, uint32_t& network, uint32_t& mask) {
    size_t slash = cidr_str.find('/');
    if (slash == std::string::npos) {
        return false;
    }

    std::string ip_part = cidr_str.substr(0, slash);
    std::string prefix_part = cidr_str.substr(slash + 1);

    // Parse prefix without exceptions; reject empty/oversized/non-numeric input.
    if (prefix_part.empty() || prefix_part.size() > 2) {
        return false;
    }
    int prefix_len = 0;
    for (char c : prefix_part) {
        if (c < '0' || c > '9') {
            return false;
        }
        prefix_len = prefix_len * 10 + (c - '0');
    }
    if (prefix_len > 32) {
        return false;
    }

    uint32_t base_ip = 0;
    if (!parseIPv4(ip_part, base_ip)) {
        return false;
    }

    // Calculate mask in host order, then convert to network-compatible byte representation
    // Since our FiveTuple IPs are in little-endian byte order (as parsed in createPacketJob)
    // we match byte-for-byte or standard bitmask.
    // Let's create mask for little-endian host representation:
    uint32_t m = 0;
    if (prefix_len > 0) {
        uint32_t big_endian_mask = 0xFFFFFFFFU << (32 - prefix_len);
        // Byte swap big_endian_mask to match parseIPv4 layout
        uint8_t b1 = (big_endian_mask >> 24) & 0xFF;
        uint8_t b2 = (big_endian_mask >> 16) & 0xFF;
        uint8_t b3 = (big_endian_mask >> 8)  & 0xFF;
        uint8_t b4 = (big_endian_mask >> 0)  & 0xFF;
        m = static_cast<uint32_t>(b1) |
            (static_cast<uint32_t>(b2) << 8) |
            (static_cast<uint32_t>(b3) << 16) |
            (static_cast<uint32_t>(b4) << 24);
    }

    mask = m;
    network = base_ip & mask;
    return true;
}

bool VPNDetector::addCIDR(const std::string& cidr_str, const std::string& label) {
    uint32_t network = 0;
    uint32_t mask = 0;
    if (!parseCIDR(cidr_str, network, mask)) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    ranges_.push_back({network, mask, cidr_str, label});
    return true;
}

bool VPNDetector::loadVPNRanges(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        // Only warn when an explicit path was provided (non-empty). The
        // default path may be missing in build/test directories; suppress
        // noise in that case.
        (void)filepath;
        return false;
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());

    // Light-weight JSON parser for {"cidr": "...", "name": "..."} entries
    size_t pos = 0;
    size_t count = 0;
    while ((pos = content.find("\"cidr\"", pos)) != std::string::npos) {
        size_t colon = content.find(':', pos);
        if (colon == std::string::npos) break;
        size_t q1 = content.find('"', colon);
        if (q1 == std::string::npos) break;
        size_t q2 = content.find('"', q1 + 1);
        if (q2 == std::string::npos) break;

        std::string cidr = content.substr(q1 + 1, q2 - q1 - 1);

        std::string label = "VPN";
        size_t name_pos = content.find("\"name\"", q2);
        if (name_pos != std::string::npos && name_pos < q2 + 100) {
            size_t n_colon = content.find(':', name_pos);
            if (n_colon != std::string::npos) {
                size_t n_q1 = content.find('"', n_colon);
                size_t n_q2 = content.find('"', n_q1 + 1);
                if (n_q1 != std::string::npos && n_q2 != std::string::npos) {
                    label = content.substr(n_q1 + 1, n_q2 - n_q1 - 1);
                }
            }
        }

        if (addCIDR(cidr, label)) {
            count++;
        }
        pos = q2 + 1;
    }

    std::cout << "[VPNDetector] Loaded " << count << " CIDR ranges from " << filepath << "\n";
    return count > 0;
}

bool VPNDetector::matchesVPNRange(uint32_t ip, std::string* label) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& range : ranges_) {
        if (range.contains(ip)) {
            if (label) {
                *label = range.label + " (" + range.cidr_str + ")";
            }
            return true;
        }
    }
    return false;
}

size_t VPNDetector::getRangeCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return ranges_.size();
}

bool VPNDetector::isWireGuard(const PacketJob& job, std::string* detail) {
    // WireGuard uses UDP, default port 51820
    if (job.tuple.protocol != 17) {
        return false;
    }

    if (job.tuple.src_port != 51820 && job.tuple.dst_port != 51820) {
        return false;
    }

    if (job.payload_length < 32 || job.payload_data == nullptr) {
        return false;
    }

    const uint8_t* p = job.payload_data;
    uint8_t msg_type = p[0];

    // WireGuard message types:
    // 1 = Handshake Initiation (148 bytes)
    // 2 = Handshake Response (92 bytes)
    // 3 = Cookie Reply (64 bytes)
    // 4 = Transport Data (>= 32 bytes)
    // All message types have 3 reserved zero bytes at bytes 1, 2, 3
    if (msg_type >= 1 && msg_type <= 4 && p[1] == 0x00 && p[2] == 0x00 && p[3] == 0x00) {
        if (detail) {
            std::string type_name;
            switch (msg_type) {
                case 1: type_name = "Handshake Initiation"; break;
                case 2: type_name = "Handshake Response"; break;
                case 3: type_name = "Cookie Reply"; break;
                case 4: type_name = "Transport Data"; break;
            }
            *detail = "WireGuard UDP:51820 [" + type_name + ", type " + std::to_string(msg_type) + "]";
        }
        return true;
    }

    return false;
}

bool VPNDetector::isOpenVPN(const PacketJob& job, std::string* detail) {
    // OpenVPN uses port 1194 over TCP or UDP
    if (job.tuple.src_port != 1194 && job.tuple.dst_port != 1194) {
        return false;
    }

    if (job.payload_length == 0 || job.payload_data == nullptr) {
        return false;
    }

    const uint8_t* p = job.payload_data;
    size_t len = job.payload_length;

    // Over TCP, OpenVPN prepends a 2-byte packet length
    if (job.tuple.protocol == 6 && len >= 3) {
        p += 2;
        len -= 2;
    }

    if (len < 1) return false;

    // Opcode is in top 5 bits of the first byte
    uint8_t opcode_byte = p[0];
    uint8_t opcode = (opcode_byte >> 3) & 0x1F;
    uint8_t op_raw = opcode_byte & 0xF8;

    // Common OpenVPN opcodes:
    // 0x38 = P_CONTROL_HARD_RESET_CLIENT_V1 / V2 (opcode 7)
    // 0x40 = P_CONTROL_HARD_RESET_SERVER_V2 (opcode 8)
    // 0x08 = P_CONTROL_HARD_RESET_CLIENT_V1 (opcode 1)
    // 0x18 = P_CONTROL_SOFT_RESET_V1 (opcode 3)
    // 0x20 = P_CONTROL_V1 (opcode 4)
    // 0x28 = P_ACK_V1 (opcode 5)
    // 0x30 = P_DATA_V1 (opcode 6)
    // 0x48 = P_DATA_V2 (opcode 9)
    if (op_raw == 0x38 || op_raw == 0x40 || op_raw == 0x08 ||
        op_raw == 0x18 || op_raw == 0x20 || op_raw == 0x28 ||
        op_raw == 0x30 || op_raw == 0x48 ||
        opcode == 1 || opcode == 6 || opcode == 7 || opcode == 8 || opcode == 9) {
        
        if (detail) {
            std::ostringstream ss;
            ss << "OpenVPN (" << (job.tuple.protocol == 6 ? "TCP" : "UDP")
               << ":1194, Opcode 0x" << std::hex << std::setw(2) << std::setfill('0')
               << static_cast<int>(op_raw) << ")";
            *detail = ss.str();
        }
        return true;
    }

    return false;
}

bool VPNDetector::isIPSec(const PacketJob& job, std::string* detail) {
    // 1. IP Protocol 50 (ESP - Encapsulating Security Payload)
    if (job.tuple.protocol == 50) {
        if (detail) *detail = "IPSec ESP (IP Protocol 50)";
        return true;
    }

    // 2. IP Protocol 51 (AH - Authentication Header)
    if (job.tuple.protocol == 51) {
        if (detail) *detail = "IPSec AH (IP Protocol 51)";
        return true;
    }

    // 3. UDP Port 500 (ISAKMP) or Port 4500 (IPSec NAT-Traversal)
    if (job.tuple.protocol == 17) {
        if (job.tuple.src_port == 500 || job.tuple.dst_port == 500) {
            if (detail) *detail = "IPSec ISAKMP IKE (UDP:500)";
            return true;
        }
        if (job.tuple.src_port == 4500 || job.tuple.dst_port == 4500) {
            if (detail) *detail = "IPSec NAT-Traversal (UDP:4500)";
            return true;
        }
    }

    return false;
}

VPNDetectionResult VPNDetector::detect(const PacketJob& job) const {
    VPNDetectionResult res;
    std::string detail;

    // 1. WireGuard fingerprinting
    if (isWireGuard(job, &detail)) {
        res.detected = true;
        res.type = VPNType::WIREGUARD;
        res.protocol_name = "WireGuard";
        res.detail = detail;
        return res;
    }

    // 2. OpenVPN fingerprinting
    if (isOpenVPN(job, &detail)) {
        res.detected = true;
        res.type = VPNType::OPENVPN;
        res.protocol_name = "OpenVPN";
        res.detail = detail;
        return res;
    }

    // 3. IPSec fingerprinting
    if (isIPSec(job, &detail)) {
        res.detected = true;
        res.type = VPNType::IPSEC;
        res.protocol_name = "IPSec";
        res.detail = detail;
        return res;
    }

    // 4. Known VPN IP ranges
    std::string label;
    if (matchesVPNRange(job.tuple.src_ip, &label)) {
        res.detected = true;
        res.type = VPNType::VPN_IP_RANGE;
        res.protocol_name = "VPN_Range";
        res.detail = "Src IP matched: " + label;
        return res;
    }

    if (matchesVPNRange(job.tuple.dst_ip, &label)) {
        res.detected = true;
        res.type = VPNType::VPN_IP_RANGE;
        res.protocol_name = "VPN_Range";
        res.detail = "Dst IP matched: " + label;
        return res;
    }

    return res;
}

} // namespace DPI
