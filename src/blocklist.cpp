#include "blocklist.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstdlib>

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
        if (end <= dot + 1) {
            return {};
        }
        labels.push_back(domain.substr(dot + 1, end - dot - 1));
        end = dot;
    }
    if (labels.empty() || labels.back().empty()) {
        return {};
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

void DomainTrie::insert(const std::string& domain) {
    if (domain.empty()) return;

    auto labels = getReversedLabels(domain);
    if (labels.empty()) return;

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
    }
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

Blocklist::Blocklist() {
    last_refresh_ = std::chrono::steady_clock::now();
}

Blocklist::~Blocklist() = default;

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

    // Empty labels would make a rule such as ".com" collapse into a broad
    // public-suffix match. Reject leading/interior dots instead.
    if (s.empty() || s.front() == '.' || s.back() == '.' ||
        s.find("..") != std::string::npos) {
        return "";
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

    // Remove optional authority userinfo before parsing host[:port].
    size_t userinfo_pos = s.rfind('@');
    if (userinfo_pos != std::string::npos) {
        s = s.substr(userinfo_pos + 1);
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

void Blocklist::addDomain(const std::string& domain) {
    std::string norm = normalizeDomain(domain);
    if (norm.empty()) return;

    std::lock_guard<std::mutex> lock(mutex_);
    if (domain_set_.insert(norm).second) {
        trie_.insert(norm);
    }
}

void Blocklist::addURL(const std::string& url) {
    std::string dom = extractDomainFromURL(url);
    if (!dom.empty()) {
        addDomain(dom);
    }
}

size_t Blocklist::loadFromFile(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        return 0;
    }

    std::unordered_set<std::string> parsed_domains;
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }

        std::string dom = extractDomainFromURL(line);
        if (!dom.empty()) {
            parsed_domains.insert(std::move(dom));
        }
    }

    // A refresh is a snapshot, not an append. Build the replacement while
    // parsing, then publish it under one lock so removed indicators stop
    // matching immediately and readers never observe a partial trie.
    {
        std::lock_guard<std::mutex> lock(mutex_);
        trie_.clear();
        domain_set_.clear();
        for (const auto& domain : parsed_domains) {
            domain_set_.insert(domain);
            trie_.insert(domain);
        }
    }

    {
        std::lock_guard<std::mutex> lock(refresh_mutex_);
        last_refresh_ = std::chrono::steady_clock::now();
    }
    return parsed_domains.size();
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
                      << " malicious domains from URLhaus.\n";
            return true;
        }
    }

    std::cout << "[Blocklist] Warning: Online fetch failed or empty; no production "
                 "blocklist was loaded.\n";
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
        "bad-malware.test",
        "c2-server.evilcorp.test",
        "ransomware-distrib.test",
        "urlhaus-test-malware.test",
        "trojan-payload-drop.test",
        "malicious-domain.test",
        "phishing-portal-bank.test",
        "botnet-command.test",
        "stealer-logs.test",
        "cryptominer-pool.test"
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

    // 1. Fast direct set lookup
    if (domain_set_.find(norm) != domain_set_.end()) {
        if (matched_rule) *matched_rule = norm;
        return true;
    }

    // 2. Trie lookup for subdomain matches (e.g. sub.bad-malware-domain.com)
    return trie_.matches(norm, matched_rule);
}

size_t Blocklist::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return domain_set_.size();
}

void Blocklist::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    trie_.clear();
    domain_set_.clear();
}

void Blocklist::setRefreshInterval(std::chrono::seconds interval) {
    std::lock_guard<std::mutex> lock(refresh_mutex_);
    refresh_interval_ = interval;
}

bool Blocklist::shouldRefresh() const {
    std::lock_guard<std::mutex> lock(refresh_mutex_);
    auto now = std::chrono::steady_clock::now();
    return (now - last_refresh_) > refresh_interval_;
}

} // namespace DPI
