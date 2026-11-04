#ifndef DPI_BLOCKLIST_H
#define DPI_BLOCKLIST_H

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <shared_mutex>
#include <mutex>
#include <memory>
#include <chrono>

namespace DPI {

// Reverse-domain Trie for fast subdomain matching (e.g. *.evil.com)
class DomainTrie {
public:
    DomainTrie();
    ~DomainTrie();

    // Insert domain (e.g., "evil.com" or "malware.ru")
    // Returns true if inserted, false if capacity reached or already present
    bool insert(const std::string& domain);

    // Check if domain or any parent domain is in the trie
    // e.g. "sub.evil.com" matches if "evil.com" was inserted
    bool matches(const std::string& domain, std::string* matched_rule = nullptr) const;

    void clear();
    size_t size() const { return count_; }
    void setMaxEntries(size_t max_entries) { max_entries_ = max_entries; }
    size_t getMaxEntries() const { return max_entries_; }

private:
    struct Node {
        std::unordered_map<std::string, std::unique_ptr<Node>> children;
        bool is_terminal{false};
        std::string full_domain;
    };

    std::unique_ptr<Node> root_;
    size_t count_{0};
    size_t max_entries_{50000};
};

class Blocklist {
public:
    explicit Blocklist(size_t max_entries = 50000);
    ~Blocklist();

    // Load domains/URLs from a local file (e.g. URLhaus text dump)
    size_t loadFromFile(const std::string& filepath);

    // Download URLhaus blocklist on-demand from https://urlhaus.abuse.ch/downloads/text/
    // Falls back to offline sample if download fails
    bool downloadOnline(const std::string& save_path = "urlhaus_online.txt");

    // Load bundled offline fallback sample domains
    // The synthetic fixture is opt-in; callers must provide its path.
    size_t loadBundledSample(const std::string& sample_path);

    // Add single domain or URL
    bool addDomain(const std::string& domain);
    bool addURL(const std::string& url);

    // Check if a domain/SNI matches malicious blocklist
    bool isBlocked(const std::string& domain, std::string* matched_rule = nullptr) const;

    // Extract domain from URL string
    static std::string extractDomainFromURL(const std::string& url);

    // Normalize domain (lowercase, strip trailing dot and whitespace)
    static std::string normalizeDomain(const std::string& domain);

    // Guard against over-aggressive matching: rejects bare TLDs, single-label domains,
    // and whitelisted major platform root domains
    static bool isValidMaliciousDomain(const std::string& domain);

    // IPv4 validation helpers
    static bool isIPv4(const std::string& str);
    static bool isPrivateOrLoopbackIP(const std::string& ip_str);

    // Check staleness of blocklist file
    static bool checkStaleness(const std::string& filepath, int max_age_days = 7, int* out_days_old = nullptr);

    // Bounded memory management
    void setMaxEntries(size_t max_entries);
    size_t getMaxEntries() const;

    // Total domains loaded
    size_t size() const;

    // Refresh management
    void setRefreshInterval(std::chrono::seconds interval);
    std::chrono::seconds getRefreshInterval() const;
    bool shouldRefresh() const;

    void clear();

private:
    mutable std::mutex mutex_;
    size_t max_entries_{50000};
    DomainTrie trie_;
    std::unordered_set<std::string> domain_set_;
    std::unordered_set<std::string> ip_set_;
    std::string source_url_{"https://urlhaus.abuse.ch/downloads/text/"};
    mutable std::mutex refresh_mutex_;
    std::chrono::steady_clock::time_point last_refresh_;
    std::chrono::seconds refresh_interval_{std::chrono::hours(24)};
    std::string last_loaded_file_;
};

} // namespace DPI

#endif // DPI_BLOCKLIST_H
