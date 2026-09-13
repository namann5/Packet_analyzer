#ifndef RULES_STORE_H
#define RULES_STORE_H

#include <cstdint>
#include <string>
#include <vector>

namespace DPI {

// A single persistent blocking rule.
struct RuleEntry {
    int64_t id = 0;
    std::string type;    // "ip" | "app" | "domain" | "port"
    std::string value;   // e.g. "10.0.0.5", "YouTube", "*.tiktok.com", "443"
    bool enabled = true;
    std::string note;
};

// ============================================================================
// RulesStore - persistent rule storage with CRUD + import/export.
//
// Persists as JSON on disk so rules survive restarts and are portable
// across machines. Loaded rules can be applied to a RuleManager so an
// engine picks them up at startup.
// ============================================================================
class RulesStore {
public:
    // Load rules from a JSON file (merges with anything current).
    bool load(const std::string& path, std::string& error);

    // Save rules to a JSON file.
    bool save(const std::string& path, std::string& error) const;

    // ---- CRUD --------------------------------------------------------------

    // Adds a rule. Returns its assigned id, or -1 on failure.
    int64_t addRule(const std::string& type,
                    const std::string& value,
                    bool enabled,
                    const std::string& note,
                    std::string& error);

    bool deleteRule(int64_t id);

    bool setEnabled(int64_t id, bool enabled);

    void clear();

    // ---- Accessors -----------------------------------------------------------

    const std::vector<RuleEntry>& rules() const { return rules_; }
    bool empty() const { return rules_.empty(); }
    size_t size() const { return rules_.size(); }

    // Applies currently loaded rules to a RuleManager.
    bool applyTo(class RuleManager& rm, std::string& error) const;

private:
    std::vector<RuleEntry> rules_;
    int64_t next_id_ = 1;
};

} // namespace DPI

#endif // RULES_STORE_H