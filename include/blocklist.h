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
    void insert(const std::string& domain);

    // Check if domain or any parent domain is in the trie
    // e.g. "sub.evil.com" matches if "evil.com" was inserted
    bool matches(const std::string& domain, std::string* matched_rule = nullptr) const;

    void clear();
    size_t size() const { return count_; }

private:
    struct Node {
        std::unordered_map<std::string, std::unique_ptr<Node>> children;
        bool is_terminal{false};
        std::string full_domain;
    };

    std::unique_ptr<Node> root_;
    size_t count_{0};
};

class Blocklist {
public:
    Blocklist();
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
    void addDomain(const std::string& domain);
    void addURL(const std::string& url);

    // Check if a domain/SNI matches malicious blocklist
    bool isBlocked(const std::string& domain, std::string* matched_rule = nullptr) const;

    // Extract domain from URL string
    static std::string extractDomainFromURL(const std::string& url);

    // Normalize domain (lowercase, strip trailing dot and whitespace)
    static std::string normalizeDomain(const std::string& domain);

    // Total domains loaded
    size_t size() const;

    // Refresh management
    void setRefreshInterval(std::chrono::seconds interval);
    bool shouldRefresh() const;

    void clear();

private:
    mutable std::mutex mutex_;
    DomainTrie trie_;
    std::unordered_set<std::string> domain_set_;
    std::string source_url_{"https://urlhaus.abuse.ch/downloads/text/"};
    mutable std::mutex refresh_mutex_;
    std::chrono::steady_clock::time_point last_refresh_;
    std::chrono::seconds refresh_interval_{std::chrono::hours(24)};
};

} // namespace DPI

#endif // DPI_BLOCKLIST_H
