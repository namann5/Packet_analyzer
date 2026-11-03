#include <iostream>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <string>
#include "anomaly_detector.h"
#include "blocklist.h"
#include "vpn_detector.h"
#include "events.h"
#include "packet_parser.h"

using namespace DPI;

// Custom check that is always active, even in release builds (the standard
// assert() macro is compiled out under NDEBUG, silently disabling all checks).
static int g_failures = 0;

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::cerr << "  FAIL: " << #cond << " (" << __FILE__ << ":"        \
                      << __LINE__ << ")\n";                                    \
            ++g_failures;                                                      \
        }                                                                      \
    } while (0)

void testShannonEntropy() {
    std::cout << "[TEST] Shannon Entropy...\n";
    // Empty string
    CHECK(AnomalyDetector::calculateShannonEntropy("") == 0.0);

    // Uniform string: all same char has 0 entropy
    CHECK(AnomalyDetector::calculateShannonEntropy("aaaaaaa") == 0.0);

    // Two equal characters: -2 * (0.5 * log2(0.5)) = 1.0
    double e2 = AnomalyDetector::calculateShannonEntropy("ab");
    CHECK(std::abs(e2 - 1.0) < 0.001);

    // High entropy random hex/base64 string
    std::string high_entropy = "a9f8b7c6d5e4f3a2b1c0d9e8f7a6b5c4";
    double e_high = AnomalyDetector::calculateShannonEntropy(high_entropy);
    std::cout << "  Entropy of hex payload: " << e_high << "\n";
    CHECK(e_high > 3.5);

    if (g_failures == 0) {
        std::cout << "  PASS: Shannon Entropy\n";
    } else {
        std::cout << "  PARTIAL: Shannon Entropy (failures detected)\n";
    }
}

void testDomainDepthAndLabels() {
    std::cout << "[TEST] Domain Depth and Labels...\n";

    auto labels = AnomalyDetector::splitDomainLabels("a.b.c.d.example.com");
    CHECK(labels.size() == 6);
    if (labels.size() >= 6) {
        CHECK(labels[0] == "a");
        CHECK(labels[5] == "com");
    }

    size_t depth = AnomalyDetector::calculateDomainDepth("data.tunnel.sub.evilcorp.com");
    CHECK(depth == 4);

    if (g_failures == 0) {
        std::cout << "  PASS: Domain Depth\n";
    } else {
        std::cout << "  PARTIAL: Domain Depth (failures detected)\n";
    }
}

void testDNSTunnelHeuristics() {
    std::cout << "[TEST] DNS Tunneling Heuristics...\n";

    AnomalyDetector::Config cfg;
    cfg.dns_tunnel_min_depth = 4;
    cfg.dns_tunnel_min_label_len = 20;
    cfg.dns_tunnel_min_entropy = 3.8;
    AnomalyDetector detector(cfg);

    PacketJob normal_job;
    normal_job.tuple.src_ip = 0x0101A8C0; // 192.168.1.1
    normal_job.tuple.dst_ip = 0x08080808; // 8.8.8.8
    normal_job.ts_sec = 1000;
    normal_job.ts_usec = 0;

    // Normal query (depth 2) -> false
    CHECK(!detector.inspectDNSQuery(normal_job, "www.google.com"));

    // Tunnel query (depth 4, long hex label > 20 chars with high entropy)
    std::string tunnel_query = "a9f8b7c6d5e4f3a2b1c0d9e8f7a6.v1.tunnel.badactor.com";
    bool tunnel_detected = detector.inspectDNSQuery(normal_job, tunnel_query);
    CHECK(tunnel_detected);

    if (g_failures == 0) {
        std::cout << "  PASS: DNS Tunneling Detection\n";
    } else {
        std::cout << "  PARTIAL: DNS Tunneling Detection (failures detected)\n";
    }
}

void testPortScanDetector() {
    std::cout << "[TEST] Port Scan Detector...\n";

    AnomalyDetector::Config cfg;
    cfg.port_scan_window_sec = 5.0;
    cfg.port_scan_threshold = 15;
    AnomalyDetector detector(cfg);

    uint32_t attacker_ip = 0x0A000001; // 1.0.0.10
    uint32_t target_ip = 0x0A000002;   // 2.0.0.10

    // Send 15 packets to different ports (<= threshold)
    for (uint16_t port = 1; port <= 15; port++) {
        PacketJob job;
        job.tuple.src_ip = attacker_ip;
        job.tuple.dst_ip = target_ip;
        job.tuple.src_port = 50000;
        job.tuple.dst_port = port;
        job.tuple.protocol = 6;
        job.ts_sec = 100;
        job.ts_usec = port * 1000;
        CHECK(!detector.processPacket(job));
    }

    // 16th port breaches threshold (> 15 distinct ports) -> triggers PORT_SCAN
    PacketJob job16;
    job16.tuple.src_ip = attacker_ip;
    job16.tuple.dst_ip = target_ip;
    job16.tuple.src_port = 50000;
    job16.tuple.dst_port = 16;
    job16.tuple.protocol = 6;
    job16.ts_sec = 100;
    job16.ts_usec = 16000;

    bool breach = detector.processPacket(job16);
    CHECK(breach);
    CHECK(detector.isIPAutoBlocked(attacker_ip));

    if (g_failures == 0) {
        std::cout << "  PASS: Port Scan Detection\n";
    } else {
        std::cout << "  PARTIAL: Port Scan Detection (failures detected)\n";
    }
}

void testSYNFloodDetector() {
    std::cout << "[TEST] SYN Flood Detector...\n";

    AnomalyDetector::Config cfg;
    cfg.syn_flood_window_sec = 1.0;
    cfg.syn_flood_threshold = 50; // Use 50 for quick unit test
    AnomalyDetector detector(cfg);

    uint32_t target_ip = 0x0A000064; // 100.0.0.10

    for (int i = 0; i < 50; i++) {
        PacketJob job;
        job.tuple.src_ip = 0x0A000001 + i;
        job.tuple.dst_ip = target_ip;
        job.tuple.src_port = 40000 + i;
        job.tuple.dst_port = 80;
        job.tuple.protocol = 6;
        job.tcp_flags = 0x02; // SYN only
        job.payload_length = 0;
        job.ts_sec = 200;
        job.ts_usec = i * 10000;
        detector.processPacket(job);
    }

    // 51st SYN breaches threshold (> 50 in 1s)
    PacketJob trigger_job;
    trigger_job.tuple.src_ip = 0x0A0000FE;
    trigger_job.tuple.dst_ip = target_ip;
    trigger_job.tuple.src_port = 45000;
    trigger_job.tuple.dst_port = 80;
    trigger_job.tuple.protocol = 6;
    trigger_job.tcp_flags = 0x02; // SYN only
    trigger_job.payload_length = 0;
    trigger_job.ts_sec = 200;
    trigger_job.ts_usec = 510000;

    bool flooded = detector.processPacket(trigger_job);
    CHECK(flooded);

    if (g_failures == 0) {
        std::cout << "  PASS: SYN Flood Detection\n";
    } else {
        std::cout << "  PARTIAL: SYN Flood Detection (failures detected)\n";
    }
}

void testBlocklistTrieAndMatching() {
    std::cout << "[TEST] URLhaus Blocklist & Domain Trie...\n";

    Blocklist bl;
    bl.addDomain("malicious-domain.com");
    bl.addURL("http://evil-c2.org/download/trojan.exe");
    bl.addDomain("phishing-bank.net");

    // Exact matches
    CHECK(bl.isBlocked("malicious-domain.com"));
    CHECK(bl.isBlocked("evil-c2.org"));
    CHECK(bl.isBlocked("phishing-bank.net"));

    // Subdomain matches via Trie
    CHECK(bl.isBlocked("sub.malicious-domain.com"));
    CHECK(bl.isBlocked("payload.cdn.evil-c2.org"));

    // Unblocked domains
    CHECK(!bl.isBlocked("google.com"));
    CHECK(!bl.isBlocked("example.com"));

    // URL normalization
    CHECK(Blocklist::extractDomainFromURL("https://c2.test.com:8443/api?x=1") == "c2.test.com");

    if (g_failures == 0) {
        std::cout << "  PASS: Blocklist & Trie Matching\n";
    } else {
        std::cout << "  PARTIAL: Blocklist & Trie Matching (failures detected)\n";
    }
}

void testVPNDetection() {
    std::cout << "[TEST] VPN Protocol Fingerprinting...\n";

    VPNDetector vpn;
    vpn.addCIDR("10.8.0.0/24", "OpenVPN Subnet");

    // 1. WireGuard Handshake Initiation packet (UDP 51820, type 1, 3 zero reserved bytes, >= 32 bytes)
    std::vector<uint8_t> wg_data(148, 0x00);
    wg_data[0] = 0x01; // Type 1: Handshake initiation
    wg_data[1] = 0x00; // Reserved
    wg_data[2] = 0x00; // Reserved
    wg_data[3] = 0x00; // Reserved

    PacketJob wg_job;
    wg_job.tuple.protocol = 17; // UDP
    wg_job.tuple.src_port = 51820;
    wg_job.tuple.dst_port = 51820;
    wg_job.payload_data = wg_data.data();
    wg_job.payload_length = wg_data.size();

    auto wg_res = vpn.detect(wg_job);
    CHECK(wg_res.detected);
    CHECK(wg_res.type == VPNType::WIREGUARD);

    // 2. OpenVPN Reset packet (UDP 1194, opcode 0x38)
    std::vector<uint8_t> ovpn_data = {0x38, 0x01, 0x02, 0x03, 0x04};
    PacketJob ovpn_job;
    ovpn_job.tuple.protocol = 17;
    ovpn_job.tuple.src_port = 1194;
    ovpn_job.tuple.dst_port = 1194;
    ovpn_job.payload_data = ovpn_data.data();
    ovpn_job.payload_length = ovpn_data.size();

    auto ovpn_res = vpn.detect(ovpn_job);
    CHECK(ovpn_res.detected);
    CHECK(ovpn_res.type == VPNType::OPENVPN);

    // 3. IPSec ESP (Protocol 50)
    PacketJob esp_job;
    esp_job.tuple.protocol = 50;
    auto esp_res = vpn.detect(esp_job);
    CHECK(esp_res.detected);
    CHECK(esp_res.type == VPNType::IPSEC);

    // 4. IPSec AH (Protocol 51)
    PacketJob ah_job;
    ah_job.tuple.protocol = 51;
    auto ah_res = vpn.detect(ah_job);
    CHECK(ah_res.detected);
    CHECK(ah_res.type == VPNType::IPSEC);

    // 5. VPN CIDR Range match (10.8.0.50 matching 10.8.0.0/24)
    PacketJob cidr_job;
    // 10.8.0.50 in little endian = 10 | (8<<8) | (0<<16) | (50<<24) = 0x3200080A
    cidr_job.tuple.src_ip = 0x3200080A;
    cidr_job.tuple.dst_ip = 0x08080808;
    cidr_job.tuple.protocol = 6;
    auto cidr_res = vpn.detect(cidr_job);
    CHECK(cidr_res.detected);
    CHECK(cidr_res.type == VPNType::VPN_IP_RANGE);

    if (g_failures == 0) {
        std::cout << "  PASS: VPN Detection\n";
    } else {
        std::cout << "  PARTIAL: VPN Detection (failures detected)\n";
    }
}

void testBlocklistValidationAndBounds() {
    std::cout << "[TEST] Blocklist Domain Validation, Bounded Capacity & Staleness...\n";

    // 1. Validation checks
    CHECK(Blocklist::isValidMaliciousDomain("bad-domain.com"));
    CHECK(Blocklist::isValidMaliciousDomain("c2.evil-corp.ru"));
    CHECK(Blocklist::isValidMaliciousDomain("sub.payload-drop.org"));
    CHECK(Blocklist::isValidMaliciousDomain("185.196.8.220")); // public IP

    // Over-aggressive matching guards:
    // Rejects bare TLDs
    CHECK(!Blocklist::isValidMaliciousDomain("com"));
    CHECK(!Blocklist::isValidMaliciousDomain("org"));
    CHECK(!Blocklist::isValidMaliciousDomain("ru"));
    CHECK(!Blocklist::isValidMaliciousDomain("top"));
    CHECK(!Blocklist::isValidMaliciousDomain("xyz"));

    // Rejects single label / invalid tokens
    CHECK(!Blocklist::isValidMaliciousDomain("localhost"));
    CHECK(!Blocklist::isValidMaliciousDomain("malware"));

    // Rejects core platform whitelisted root domains to prevent catastrophic over-blocking
    CHECK(!Blocklist::isValidMaliciousDomain("google.com"));
    CHECK(!Blocklist::isValidMaliciousDomain("github.com"));
    CHECK(!Blocklist::isValidMaliciousDomain("cloudflare.com"));
    CHECK(!Blocklist::isValidMaliciousDomain("microsoft.com"));
    CHECK(!Blocklist::isValidMaliciousDomain("apple.com"));

    // Rejects private and loopback IPs
    CHECK(!Blocklist::isValidMaliciousDomain("127.0.0.1"));
    CHECK(!Blocklist::isValidMaliciousDomain("10.0.0.1"));
    CHECK(!Blocklist::isValidMaliciousDomain("192.168.1.1"));
    CHECK(!Blocklist::isValidMaliciousDomain("172.16.0.1"));

    // 2. Bounded capacity check
    Blocklist capped(3);
    CHECK(capped.addDomain("malware1.com"));
    CHECK(capped.addDomain("malware2.com"));
    CHECK(capped.addDomain("malware3.com"));
    // 4th and 5th should be rejected because capacity is 3
    CHECK(!capped.addDomain("malware4.com"));
    CHECK(!capped.addDomain("malware5.com"));
    CHECK(capped.size() == 3);

    // 3. Staleness check
    int days_old = 0;
    // Current data/urlhaus_sample.txt has today's date (2026-11-03) -> not stale
    CHECK(!Blocklist::checkStaleness("data/urlhaus_sample.txt", 7, &days_old));

    if (g_failures == 0) {
        std::cout << "  PASS: Blocklist Domain Validation, Bounded Capacity & Staleness\n";
    } else {
        std::cout << "  PARTIAL: Blocklist Domain Validation, Bounded Capacity & Staleness (failures detected)\n";
    }
}

void testVPNActionsAndCuratedRanges() {
    std::cout << "[TEST] VPN Action (Flag-Only vs Block) & Curated CIDRs...\n";

    // 1. VPN Action modes
    VPNDetector::Config cfg;
    cfg.action = VPNAction::FLAG_ONLY;
    VPNDetector detector_flag(cfg);
    CHECK(!detector_flag.isBlock());
    CHECK(detector_flag.getAction() == VPNAction::FLAG_ONLY);

    detector_flag.setAction(VPNAction::BLOCK);
    CHECK(detector_flag.isBlock());
    CHECK(detector_flag.getAction() == VPNAction::BLOCK);

    detector_flag.setBlockVPN(false);
    CHECK(!detector_flag.isBlock());

    // 2. Curated CIDR detection from data/vpn_ranges.json
    VPNDetector curated_vpn;
    bool loaded = curated_vpn.loadVPNRanges("data/vpn_ranges.json");
    CHECK(loaded);
    CHECK(curated_vpn.getRangeCount() >= 10);

    // Helper to build IP in little endian (matches parseIPv4 layout)
    auto makeIP = [](uint8_t a, uint8_t b, uint8_t c, uint8_t d) -> uint32_t {
        return static_cast<uint32_t>(a) |
               (static_cast<uint32_t>(b) << 8) |
               (static_cast<uint32_t>(c) << 16) |
               (static_cast<uint32_t>(d) << 24);
    };

    // Test Mullvad (193.138.218.45 in 193.138.218.0/24)
    PacketJob job_mullvad;
    job_mullvad.tuple.src_ip = makeIP(193, 138, 218, 45);
    job_mullvad.tuple.dst_ip = makeIP(8, 8, 8, 8);
    job_mullvad.tuple.protocol = 6;
    auto res_m = curated_vpn.detect(job_mullvad);
    CHECK(res_m.detected);
    CHECK(res_m.type == VPNType::VPN_IP_RANGE);

    // Test ProtonVPN (185.159.157.10 in 185.159.157.0/24)
    PacketJob job_proton;
    job_proton.tuple.src_ip = makeIP(185, 159, 157, 10);
    job_proton.tuple.dst_ip = makeIP(8, 8, 8, 8);
    job_proton.tuple.protocol = 6;
    auto res_p = curated_vpn.detect(job_proton);
    CHECK(res_p.detected);

    // Test NordVPN (185.220.101.5 in 185.220.101.0/24)
    PacketJob job_nord;
    job_nord.tuple.src_ip = makeIP(185, 220, 101, 5);
    job_nord.tuple.dst_ip = makeIP(8, 8, 8, 8);
    job_nord.tuple.protocol = 6;
    auto res_n = curated_vpn.detect(job_nord);
    CHECK(res_n.detected);

    // Test Non-VPN regular IP (142.250.190.46 - Google)
    PacketJob job_normal;
    job_normal.tuple.src_ip = makeIP(142, 250, 190, 46);
    job_normal.tuple.dst_ip = makeIP(192, 168, 1, 10);
    job_normal.tuple.protocol = 6;
    auto res_norm = curated_vpn.detect(job_normal);
    CHECK(!res_norm.detected);

    if (g_failures == 0) {
        std::cout << "  PASS: VPN Action Modes & Curated CIDRs\n";
    } else {
        std::cout << "  PARTIAL: VPN Action Modes & Curated CIDRs (failures detected)\n";
    }
}

int main() {
    std::cout << "========================================\n";
    std::cout << "Running Track B Unit & Integration Tests\n";
    std::cout << "========================================\n";

    testShannonEntropy();
    testDomainDepthAndLabels();
    testDNSTunnelHeuristics();
    testPortScanDetector();
    testSYNFloodDetector();
    testBlocklistTrieAndMatching();
    testBlocklistValidationAndBounds();
    testVPNDetection();
    testVPNActionsAndCuratedRanges();

    if (g_failures != 0) {
        std::cerr << "\n" << g_failures << " TRACK B TEST(S) FAILED\n";
        return 1;
    }
    std::cout << "\nALL TRACK B UNIT TESTS PASSED SUCCESSFULLY! (9/9)\n";
    return 0;
}
