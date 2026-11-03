#include "blocklist.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <ctime>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#include <urlmon.h>
#pragma comment(lib, "urlmon.lib")
#else
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#endif

namespace DPI {

// ============================================================================
// DomainTrie Implementation
// ============================================================================

DomainTrie::DomainTrie()
    : root_(std::make_unique<Node>()) {
}

DomainTrie::~DomainTrie() = default;

void DomainTrie::clear() {
    root_ = std::make_unique<Node>();
    count_ = 0;
}

namespace {

std::vector<std::string> getReversedLabels(const std::string& domain) {
    std::vector<std::string> labels;
    if (domain.empty()) return labels;

    size_t end = domain.length();
    while (end > 0) {
        size_t dot = domain.rfind('.', end - 1);
        if (dot == std::string::npos) {
            labels.push_back(domain.substr(0, end));
            break;
        }
        if (end > dot + 1) {
            labels.push_back(domain.substr(dot + 1, end - dot - 1));
        }
        end = dot;
    }
    return labels;
}

// Download a URL to a local file using curl via argv (no shell interpolation).
// Returns true on success. No-op on Windows (native URLDownloadToFileA is used).
bool runCurlDownload(const std::string& url, const std::string& out_path) {
#ifdef _WIN32
    (void)url;
    (void)out_path;
    return false;
#else
    pid_t pid = fork();
    if (pid < 0) {
        return false;
    }
    if (pid == 0) {
        // Child: never touches the shell, so the URL/path cannot be injected.
        execlp("curl", "curl", "-s", "-f", "-L", "--connect-timeout", "10", "--max-time", "30",
               url.c_str(), "-o", out_path.c_str(),
               static_cast<char*>(nullptr));
        _exit(127);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            return false;
        }
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
#endif
}

} // namespace

bool DomainTrie::insert(const std::string& domain) {
    if (domain.empty()) return false;
    if (count_ >= max_entries_) return false;

    auto labels = getReversedLabels(domain);
    if (labels.empty()) return false;

    Node* curr = root_.get();
    for (const auto& label : labels) {
        auto& child = curr->children[label];
        if (!child) {
            child = std::make_unique<Node>();
        }
        curr = child.get();
    }

    if (!curr->is_terminal) {
        curr->is_terminal = true;
        curr->full_domain = domain;
        count_++;
        return true;
    }
    return false;
}

bool DomainTrie::matches(const std::string& domain, std::string* matched_rule) const {
    if (domain.empty()) return false;

    auto labels = getReversedLabels(domain);
    if (labels.empty()) return false;

    const Node* curr = root_.get();
    for (const auto& label : labels) {
        auto it = curr->children.find(label);
        if (it == curr->children.end()) {
            return false;
        }
        curr = it->second.get();
        if (curr->is_terminal) {
            if (matched_rule) {
                *matched_rule = curr->full_domain;
            }
            return true;
        }
    }

    return curr->is_terminal;
}

// ============================================================================
// Blocklist Implementation
// ============================================================================

Blocklist::Blocklist(size_t max_entries)
    : max_entries_(max_entries) {
    trie_.setMaxEntries(max_entries);
    last_refresh_ = std::chrono::steady_clock::now();
}

Blocklist::~Blocklist() = default;

void Blocklist::setMaxEntries(size_t max_entries) {
    std::lock_guard<std::mutex> lock(mutex_);
    max_entries_ = max_entries;
    trie_.setMaxEntries(max_entries);
}

size_t Blocklist::getMaxEntries() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return max_entries_;
}

bool Blocklist::isIPv4(const std::string& str) {
    if (str.empty()) return false;
    int octets = 0;
    int val = 0;
    bool has_digit = false;
    for (char c : str) {
        if (c == '.') {
            if (!has_digit || val < 0 || val > 255) return false;
            octets++;
            val = 0;
            has_digit = false;
        } else if (c >= '0' && c <= '9') {
            val = val * 10 + (c - '0');
            if (val > 255) return false;
            has_digit = true;
        } else {
            return false;
        }
    }
    if (!has_digit || val < 0 || val > 255) return false;
    return octets == 3;
}

bool Blocklist::isPrivateOrLoopbackIP(const std::string& ip_str) {
    if (!isIPv4(ip_str)) return false;
    std::stringstream ss(ip_str);
    int o1 = 0, o2 = 0, o3 = 0, o4 = 0;
    char dot;
    if (!(ss >> o1 >> dot >> o2 >> dot >> o3 >> dot >> o4)) return false;

    // Loopback
    if (o1 == 127 || o1 == 0) return true;
    // 10.0.0.0/8
    if (o1 == 10) return true;
    // 172.16.0.0/12
    if (o1 == 172 && (o2 >= 16 && o2 <= 31)) return true;
    // 192.168.0.0/16
    if (o1 == 192 && o2 == 168) return true;
    // 169.254.0.0/16 (Link-local)
    if (o1 == 169 && o2 == 254) return true;
    // Broadcast
    if (o1 == 255 && o2 == 255 && o3 == 255 && o4 == 255) return true;

    return false;
}

bool Blocklist::isValidMaliciousDomain(const std::string& domain) {
    if (domain.length() < 3 || domain.length() > 253) return false;

    // Public IPv4 address check
    if (isIPv4(domain)) {
        return !isPrivateOrLoopbackIP(domain);
    }

    // Must not start or end with dot, no consecutive dots
    if (domain.front() == '.' || domain.back() == '.' || domain.find("..") != std::string::npos) {
        return false;
    }

    // Must contain only lowercase letters, digits, hyphens, and dots
    for (char c : domain) {
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.')) {
            return false;
        }
    }

    // Split into labels
    std::vector<std::string> labels;
    size_t start = 0;
    while (start < domain.length()) {
        size_t dot = domain.find('.', start);
        if (dot == std::string::npos) {
            labels.push_back(domain.substr(start));
            break;
        }
        labels.push_back(domain.substr(start, dot - start));
        start = dot + 1;
    }

    // Guard against bare TLDs or single-token hostnames
    if (labels.size() < 2) {
        return false;
    }

    for (const auto& l : labels) {
        if (l.empty() || l.length() > 63) return false;
        if (l.front() == '-' || l.back() == '-') return false;
    }

    // Bare top-level domains list
    static const std::unordered_set<std::string> kBareTLDs = {
        "com", "org", "net", "edu", "gov", "mil", "int", "arpa",
        "ru", "cn", "de", "uk", "nl", "fr", "it", "es", "pl", "br",
        "top", "xyz", "info", "biz", "online", "site", "club", "cc",
        "vip", "work", "live", "link", "icu", "tk", "ga", "cf", "ml", "gq"
    };
    if (kBareTLDs.find(domain) != kBareTLDs.end()) {
        return false;
    }

    // Safe platform whitelist:
    // Reject direct blocking of core platform roots (e.g. google.com, github.com)
    // to prevent over-aggressive blocking if a user-generated malware URL was on that platform.
    static const std::unordered_set<std::string> kWhitelistedRootDomains = {
        "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
        "youtube.com", "youtu.be",
        "github.com", "githubusercontent.com", "gitlab.com",
        "microsoft.com", "windows.net", "azure.com", "office.com", "live.com", "msn.com",
        "apple.com", "icloud.com",
        "cloudflare.com", "cloudflare-dns.com",
        "amazon.com", "amazonaws.com",
        "facebook.com", "fbcdn.net",
        "twitter.com", "x.com", "t.co",
        "wikipedia.org", "wikimedia.org",
        "dropbox.com", "drive.google.com",
        "discord.com", "discordapp.com", "discord.gg",
        "telegram.org", "t.me",
        "bitly.com", "tinyurl.com"
    };

    if (kWhitelistedRootDomains.find(domain) != kWhitelistedRootDomains.end()) {
        return false;
    }

    return true;
}

bool Blocklist::checkStaleness(const std::string& filepath, int max_age_days, int* out_days_old) {
    int days_old = 0;
    bool determined = false;

    // 1. Try parsing header comment dates: "# Generated at: YYYY-MM-DD" or "# Date: YYYY-MM-DD"
    std::string actual_path = filepath;
    std::ifstream file(actual_path);
    if (!file.is_open()) {
        actual_path = "../" + filepath;
        file.open(actual_path);
    }
    if (file.is_open()) {
        std::string line;
        int lines_checked = 0;
        while (lines_checked < 30 && std::getline(file, line)) {
            lines_checked++;
            if (line.empty() || line[0] != '#') continue;

            for (size_t i = 0; i + 10 <= line.length(); ++i) {
                if (std::isdigit(line[i]) && std::isdigit(line[i+1]) &&
                    std::isdigit(line[i+2]) && std::isdigit(line[i+3]) &&
                    line[i+4] == '-' &&
                    std::isdigit(line[i+5]) && std::isdigit(line[i+6]) &&
                    line[i+7] == '-' &&
                    std::isdigit(line[i+8]) && std::isdigit(line[i+9])) {

                    try {
                        int y = std::stoi(line.substr(i, 4));
                        int m = std::stoi(line.substr(i+5, 2));
                        int d = std::stoi(line.substr(i+8, 2));

                        std::tm file_tm = {};
                        file_tm.tm_year = y - 1900;
                        file_tm.tm_mon = m - 1;
                        file_tm.tm_mday = d;
                        std::time_t file_time = std::mktime(&file_tm);
                        if (file_time > 0) {
                            std::time_t now = std::time(nullptr);
                            double diff_sec = std::difftime(now, file_time);
                            if (diff_sec > 0) {
                                days_old = static_cast<int>(diff_sec / 86400.0);
                                determined = true;
                                break;
                            }
                        }
                    } catch (...) {}
                }
            }
            if (determined) break;
        }
    }

    // 2. Fall back to filesystem last write time
    if (!determined) {
        try {
            std::filesystem::path p(actual_path);
            if (std::filesystem::exists(p)) {
                auto ftime = std::filesystem::last_write_time(p);
                auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                    ftime - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
                std::time_t cftime = std::chrono::system_clock::to_time_t(sctp);
                std::time_t now = std::time(nullptr);
                double diff_sec = std::difftime(now, cftime);
                if (diff_sec > 0) {
                    days_old = static_cast<int>(diff_sec / 86400.0);
                    determined = true;
                }
            }
        } catch (...) {}
    }

    if (out_days_old) {
        *out_days_old = days_old;
    }

    return determined && (days_old > max_age_days);
}

std::string Blocklist::normalizeDomain(const std::string& domain) {
    if (domain.empty()) return "";

    std::string s = domain;
    // Trim whitespace
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    s = s.substr(start, end - start + 1);

    // Remove trailing dot if present
    if (!s.empty() && s.back() == '.') {
        s.pop_back();
    }

    // Lowercase
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return std::tolower(c);
    });

    return s;
}

std::string Blocklist::extractDomainFromURL(const std::string& url) {
    if (url.empty()) return "";

    std::string s = url;
    // Strip scheme
    size_t scheme_pos = s.find("://");
    if (scheme_pos != std::string::npos) {
        s = s.substr(scheme_pos + 3);
    }

    // Stop at path, query, or fragment
    size_t slash_pos = s.find_first_of("/?#");
    if (slash_pos != std::string::npos) {
        s = s.substr(0, slash_pos);
    }

    // Stop at port if present
    size_t colon_pos = s.find(':');
    if (colon_pos != std::string::npos) {
        s = s.substr(0, colon_pos);
    }

    return normalizeDomain(s);
}

bool Blocklist::addDomain(const std::string& domain) {
    std::string norm = normalizeDomain(domain);
    if (norm.empty()) return false;

    if (!isValidMaliciousDomain(norm)) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (domain_set_.size() + ip_set_.size() >= max_entries_) {
        return false;
    }

    if (isIPv4(norm)) {
        return ip_set_.insert(norm).second;
    }

    if (domain_set_.insert(norm).second) {
        return trie_.insert(norm);
    }
    return false;
}

bool Blocklist::addURL(const std::string& url) {
    std::string dom = extractDomainFromURL(url);
    if (!dom.empty()) {
        return addDomain(dom);
    }
    return false;
}

size_t Blocklist::loadFromFile(const std::string& filepath) {
    std::string actual_path = filepath;
    std::ifstream file(actual_path);
    if (!file.is_open()) {
        actual_path = "../" + filepath;
        file.open(actual_path);
    }
    if (!file.is_open()) {
        return 0;
    }

    // Check staleness guard (> 7 days)
    int days_old = 0;
    if (checkStaleness(actual_path, 7, &days_old)) {
        std::cout << "[Blocklist] WARNING: Blocklist file '" << actual_path
                  << "' is stale (" << days_old << " days old). Recommended to refresh via --download-urlhaus.\n";
    }

    size_t loaded = 0;
    bool capacity_warned = false;
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }

        std::string dom = extractDomainFromURL(line);
        if (!dom.empty()) {
            if (addDomain(dom)) {
                loaded++;
            } else if (!capacity_warned && (size() >= max_entries_)) {
                std::cout << "[Blocklist] Notice: Reached maximum capacity limit of "
                          << max_entries_ << " entries. Remaining entries skipped.\n";
                capacity_warned = true;
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(refresh_mutex_);
        last_refresh_ = std::chrono::steady_clock::now();
        last_loaded_file_ = filepath;
    }
    return loaded;
}

bool Blocklist::downloadOnline(const std::string& save_path) {
    std::cout << "[Blocklist] Fetching online URLhaus list from " << source_url_ << "...\n";

    bool success = false;

#ifdef _WIN32
    // Try Windows native URLDownloadToFileA first
    HRESULT hr = URLDownloadToFileA(NULL, source_url_.c_str(), save_path.c_str(), 0, NULL);
    if (SUCCEEDED(hr)) {
        success = true;
    }
#endif

    // If native download didn't succeed, try curl via argv (no shell).
    if (!success) {
        if (runCurlDownload(source_url_, save_path)) {
            success = true;
        }
    }

    if (success) {
        size_t count = loadFromFile(save_path);
        if (count > 0) {
            std::cout << "[Blocklist] Successfully downloaded and loaded " << count
                      << " malicious entries from URLhaus (capacity: " << max_entries_ << ").\n";
            return true;
        }
    }

    std::cout << "[Blocklist] Warning: Online fetch failed; loading offline fallback sample.\n";
    loadBundledSample();
    return false;
}

size_t Blocklist::loadBundledSample(const std::string& sample_path) {
    size_t count = loadFromFile(sample_path);
    if (count > 0) {
        std::cout << "[Blocklist] Loaded " << count << " domains from bundled file: " << sample_path << "\n";
        return count;
    }

    // Default hardcoded fallback if sample file isn't found
    static const std::vector<std::string> kFallbackDomains = {
        "bad-malware-domain.com",
        "c2-server.evilcorp.biz",
        "ransomware-distrib.net",
        "urlhaus-test-malware.org",
        "trojan-payload-drop.info",
        "malicious-domain.xyz",
        "phishing-portal-bank.com",
        "botnet-command.top",
        "stealer-logs.cc",
        "cryptominer-pool.club",
        "threat-actor-c2.ru",
        "apt-backdoor-update.com"
    };

    for (const auto& d : kFallbackDomains) {
        addDomain(d);
    }

    std::cout << "[Blocklist] Loaded " << kFallbackDomains.size()
              << " fallback malicious domains into blocklist.\n";
    return kFallbackDomains.size();
}

bool Blocklist::isBlocked(const std::string& domain, std::string* matched_rule) const {
    if (domain.empty()) return false;

    std::string norm = normalizeDomain(domain);
    if (norm.empty()) return false;

    std::lock_guard<std::mutex> lock(mutex_);

    // 1. Check IP address match if domain is an IPv4 string
    if (isIPv4(norm)) {
        if (ip_set_.find(norm) != ip_set_.end()) {
            if (matched_rule) *matched_rule = norm;
            return true;
        }
        return false;
    }

    // 2. Fast direct set lookup
    if (domain_set_.find(norm) != domain_set_.end()) {
        if (matched_rule) *matched_rule = norm;
        return true;
    }

    // 3. Trie lookup for subdomain matches (e.g. sub.bad-malware-domain.com)
    return trie_.matches(norm, matched_rule);
}

size_t Blocklist::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return domain_set_.size() + ip_set_.size();
}

void Blocklist::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    trie_.clear();
    domain_set_.clear();
    ip_set_.clear();
}

void Blocklist::setRefreshInterval(std::chrono::seconds interval) {
    std::lock_guard<std::mutex> lock(refresh_mutex_);
    refresh_interval_ = interval;
}

std::chrono::seconds Blocklist::getRefreshInterval() const {
    std::lock_guard<std::mutex> lock(refresh_mutex_);
    return refresh_interval_;
}

bool Blocklist::shouldRefresh() const {
    std::lock_guard<std::mutex> lock(refresh_mutex_);
    if (refresh_interval_.count() <= 0) return false;
    auto now = std::chrono::steady_clock::now();
    return (now - last_refresh_) > refresh_interval_;
}

} // namespace DPI
