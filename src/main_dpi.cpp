#include <csignal>
#include <iostream>
#include <limits>
#include <memory>
#include <string>
#include <vector>

#include "dpi_engine.h"
#include "rules_store.h"
#include "capture_source.h"

using namespace DPI;

namespace {

// Set from the Ctrl+C handler so DPIEngine can stop live capture cleanly.
DPIEngine* g_engine = nullptr;

void onSignal(int) {
    if (g_engine) {
        g_engine->stopCapture();
    }
}

void printUsage(const char* program) {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════╗
║                    DPI ENGINE v2.0                            ║
║         Deep Packet Inspection - Live Capture + Rules         ║
╚══════════════════════════════════════════════════════════════╝

Usage: )" << program << R"( <input.pcap> <output.pcap> [options]
       )" << program << R"( -i <interface> [-o output.pcap] [options]

Modes:
  <input.pcap> <output.pcap>   Process a saved PCAP file
  -i <interface>               Capture live traffic from an interface
                               (-l lists available interfaces)

Options:
  --rules <file>          Load persistent JSON rules from file
  --block-ip <ip>         Block packets from source IP
  --block-app <app>       Block application (e.g., YouTube, Facebook)
  --block-domain <dom>    Block domain (supports wildcards: *.facebook.com)
  --export-stats [port]   Stream live JSON events to dashboard IPC port (default: 9000)
  --ipc-host <host>       Dashboard IPC host (default: 127.0.0.1)
  --ipc-port <port>       Dashboard IPC port (default: 9000)
  -o <file>               Output PCAP for forwarded traffic (live mode)
  --pcap-buffer <MiB>     Capture buffer size in MiB (default: 2; larger = fewer drops under load)
  --duration <sec>        Auto-stop live capture after N seconds (default: run until Ctrl+C)
  --lbs <n>               Number of load balancer threads (default: 2)
  --fps <n>               FP threads per LB (default: 2)
  -l, --list-interfaces   List available capture interfaces and exit
  --verbose               Enable verbose output

Security Options (Track B):
  --urlhaus <file>        Load URLhaus blocklist from file
  --download-urlhaus      Fetch latest URLhaus blocklist online
  --vpn-ranges <file>     Load VPN CIDR ranges JSON file
  --block-vpn             Block detected VPN and tunneled traffic
  --no-block-malicious    Do not auto-block malicious domains
  --port-scan-thresh <n>  Port scan unique port threshold (default: 15)
  --syn-flood-thresh <n>  SYN flood packets/sec threshold (default: 500)
  --events-out <file>     Write JSON security events to file

Examples:
  )" << program << R"( capture.pcap filtered.pcap
  )" << program << R"( -i eth0 -o live.pcap --rules rules.json --export-stats 9000
  )" << program << R"( -l
  )" << program << R"( capture.pcap filtered.pcap --block-app YouTube --rules rules.json
)";
}

bool parsePort(const std::string& str, uint16_t& out_port) {
    try {
        size_t idx = 0;
        long val = std::stol(str, &idx);
        if (idx == str.size() && val >= 1 && val <= 65535) {
            out_port = static_cast<uint16_t>(val);
            return true;
        }
    } catch (...) {}
    return false;
}

// Parse a non-negative decimal integer without throwing.
bool parseULong(const std::string& str, unsigned long& out) {
    if (str.empty()) return false;
    for (char c : str) {
        if (c < '0' || c > '9') return false;
    }
    try {
        size_t idx = 0;
        unsigned long val = std::stoul(str, &idx);
        if (idx != str.size()) return false;
        out = val;
        return true;
    } catch (...) {
        return false;
    }
}

// Parse a signed decimal integer without throwing.
bool parseInt(const std::string& str, int& out) {
    if (str.empty()) return false;
    size_t i = 0;
    if (str[0] == '-' || str[0] == '+') i = 1;
    if (i == str.size()) return false;
    for (size_t j = i; j < str.size(); ++j) {
        if (str[j] < '0' || str[j] > '9') return false;
    }
    try {
        size_t idx = 0;
        int val = std::stoi(str, &idx);
        if (idx != str.size()) return false;
        out = val;
        return true;
    } catch (...) {
        return false;
    }
}

bool optionTakesValue(const std::string& arg) {
    return arg == "--block-ip" || arg == "--block-app" || arg == "--block-domain" ||
           arg == "--ipc-host" || arg == "--ipc-port" || arg == "--rules" ||
           arg == "--urlhaus" || arg == "--vpn-ranges" ||
           arg == "--port-scan-thresh" || arg == "--syn-flood-thresh" ||
           arg == "--events-out" || arg == "--pcap-buffer" || arg == "--duration" ||
           arg == "--lbs" || arg == "--fps" || arg == "-i" || arg == "--interface" ||
           arg == "-o" || arg == "--output";
}

bool isKnownOption(const std::string& arg) {
    return optionTakesValue(arg) || arg == "--export-stats" || arg == "--ipc" ||
           arg == "--download-urlhaus" || arg == "--block-vpn" ||
           arg == "--no-block-malicious" || arg == "--verbose" ||
           arg == "--help" || arg == "-h" || arg == "-l" ||
           arg == "--list-interfaces";
}

} // namespace

int main(int argc, char* argv[]) {
    bool list_only = false;
    std::string input_file;
    std::string output_file;
    std::string live_interface;
    std::string rules_store_path;

    // Parse the full argv once.
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (optionTakesValue(arg) &&
            (i + 1 >= argc || isKnownOption(argv[i + 1]))) {
            std::cerr << "Missing value for " << arg << "\n";
            return 1;
        }
        if (arg == "-l" || arg == "--list-interfaces") {
            list_only = true;
        } else if ((arg == "-i" || arg == "--interface") && i + 1 < argc) {
            live_interface = argv[++i];
        } else if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
            output_file = argv[++i];
        } else if (arg == "--rules" && i + 1 < argc) {
            rules_store_path = argv[++i];
        }
    }

    // List available interfaces first (no engine needed).
    if (list_only) {
        auto ifaces = LiveCapture::listInterfaces();
        std::cout << "Available capture interfaces:\n";
        for (const auto& name : ifaces) {
            std::cout << "  " << name << "\n";
        }
        if (ifaces.empty()) {
            std::cout << "  (none - built without libpcap or no interfaces found)\n";
        }
        return 0;
    }

    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }
    if (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help") {
        printUsage(argv[0]);
        return 0;
    }

    int opt_start = 1;
    if (live_interface.empty()) {
        if (argv[1][0] == '-') {
            printUsage(argv[0]);
            return 1;
        }
        input_file = argv[1];
        opt_start = 2;
        if (argc >= 3 && (argv[2][0] != '-' || !isKnownOption(argv[2]))) {
            output_file = argv[2];
            opt_start = 3;
        }
    }

    DPIEngine::Config config;
    config.num_load_balancers = 2;
    config.fps_per_lb = 2;

    std::vector<std::string> block_ips;
    std::vector<std::string> block_apps;
    std::vector<std::string> block_domains;

    for (int i = opt_start; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--block-ip" && i + 1 < argc) {
            block_ips.push_back(argv[++i]);
        } else if (arg == "--block-app" && i + 1 < argc) {
            block_apps.push_back(argv[++i]);
        } else if (arg == "--block-domain" && i + 1 < argc) {
            block_domains.push_back(argv[++i]);
        } else if (arg == "--export-stats" || arg == "--ipc") {
            config.enable_ipc = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                uint16_t port = 0;
                if (parsePort(argv[i + 1], port)) {
                    config.ipc_port = port;
                    ++i;
                }
            }
        } else if (arg == "--ipc-host" && i + 1 < argc) {
            config.ipc_host = argv[++i];
            config.enable_ipc = true;
        } else if (arg == "--ipc-port" && i + 1 < argc) {
            uint16_t port = 0;
            if (parsePort(argv[++i], port)) {
                config.ipc_port = port;
                config.enable_ipc = true;
            } else {
                std::cerr << "Invalid port for --ipc-port (must be 1-65535): " << argv[i] << "\n";
                return 1;
            }
        } else if (arg == "--rules" && i + 1 < argc) {
            rules_store_path = argv[++i];
        } else if (arg == "--urlhaus" && i + 1 < argc) {
            config.blocklist_file = argv[++i];
        } else if (arg == "--download-urlhaus") {
            config.download_urlhaus = true;
        } else if (arg == "--vpn-ranges" && i + 1 < argc) {
            config.vpn_ranges_file = argv[++i];
        } else if (arg == "--block-vpn") {
            config.block_vpn = true;
        } else if (arg == "--no-block-malicious") {
            config.block_malicious = false;
        } else if (arg == "--port-scan-thresh" && i + 1 < argc) {
            unsigned long v = 0;
            if (!parseULong(argv[++i], v) || v == 0) {
                std::cerr << "Invalid value for --port-scan-thresh (must be > 0): " << argv[i] << "\n";
                return 1;
            }
            config.port_scan_threshold = static_cast<size_t>(v);
        } else if (arg == "--syn-flood-thresh" && i + 1 < argc) {
            unsigned long v = 0;
            if (!parseULong(argv[++i], v) || v == 0) {
                std::cerr << "Invalid value for --syn-flood-thresh (must be > 0): " << argv[i] << "\n";
                return 1;
            }
            config.syn_flood_threshold = static_cast<size_t>(v);
        } else if (arg == "--events-out" && i + 1 < argc) {
            config.events_output_file = argv[++i];
        } else if (arg == "--pcap-buffer" && i + 1 < argc) {
            unsigned long v = 0;
            constexpr unsigned long max_buffer_mib =
                static_cast<unsigned long>(std::numeric_limits<int>::max()) /
                (1024UL * 1024UL);
            if (!parseULong(argv[++i], v) || v == 0 || v > max_buffer_mib) {
                std::cerr << "Invalid value for --pcap-buffer (MiB, must be > 0): " << argv[i] << "\n";
                return 1;
            }
            config.pcap_buffer_bytes = static_cast<uint32_t>(v * 1024UL * 1024UL);
        } else if (arg == "--duration" && i + 1 < argc) {
            unsigned long v = 0;
            if (!parseULong(argv[++i], v) || v == 0 ||
                v > static_cast<unsigned long>(std::numeric_limits<uint32_t>::max())) {
                std::cerr << "Invalid value for --duration (seconds, must be > 0): " << argv[i] << "\n";
                return 1;
            }
            config.duration_sec = static_cast<uint32_t>(v);
        } else if (arg == "--lbs" && i + 1 < argc) {
            int v = 0;
            if (!parseInt(argv[++i], v) || v <= 0) {
                std::cerr << "Invalid value for --lbs (must be a positive integer): " << argv[i] << "\n";
                return 1;
            }
            config.num_load_balancers = v;
        } else if (arg == "--fps" && i + 1 < argc) {
            int v = 0;
            if (!parseInt(argv[++i], v) || v <= 0) {
                std::cerr << "Invalid value for --fps (must be a positive integer): " << argv[i] << "\n";
                return 1;
            }
            config.fps_per_lb = v;
        } else if (arg == "--verbose") {
            config.verbose = true;
        } else if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            return 0;
        } else if ((arg == "-i" || arg == "--interface" ||
                    arg == "-o" || arg == "--output") && i + 1 < argc) {
            ++i;
        } else {
            std::cerr << "Unknown option or missing value: " << arg << "\n";
            printUsage(argv[0]);
            return 1;
        }
    }

    // Create DPI engine
    DPIEngine engine(config);
    g_engine = &engine;

    // Initialize
    if (!engine.initialize()) {
        std::cerr << "Failed to initialize DPI engine\n";
        return 1;
    }

    // Persistent rules first (they may supply blocking rules).
    if (!rules_store_path.empty()) {
        RulesStore store;
        std::string error;
        if (!store.load(rules_store_path, error)) {
            std::cerr << "[main] " << error << "\n";
            return 1;
        }
        if (!store.applyTo(engine.getRuleManager(), error)) {
            std::cerr << "[main] Failed to apply rules: " << error << "\n";
            return 1;
        }
        std::cout << "[main] Applied " << store.size()
                  << " persistent rules from " << rules_store_path << "\n";
    }

    // Apply command-line blocking rules
    for (const auto& ip : block_ips) engine.blockIP(ip);
    for (const auto& app : block_apps) engine.blockApp(app);
    for (const auto& domain : block_domains) engine.blockDomain(domain);

    // Install Ctrl+C handler for live capture stop.
    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);

    bool ok;
    if (!live_interface.empty()) {
        ok = engine.processLive(live_interface, output_file);
    } else {
        ok = engine.processFile(input_file, output_file);
    }

    g_engine = nullptr;
    return ok ? 0 : 1;
}
