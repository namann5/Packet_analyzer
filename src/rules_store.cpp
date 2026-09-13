#include "rules_store.h"
#include "rule_manager.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <unordered_map>

namespace DPI {

// ============================================================================
// Minimal JSON reader/writer (RFC-8259 subset) - zero external dependencies.
// Supports objects, arrays, strings, numbers, booleans and null, which is
// everything the rules file needs.
// ============================================================================

namespace jsonlite {

struct Value {
    enum class Type { Null, Bool, Number, String, Array, Object };

    Type type = Type::Null;
    bool boolean = false;
    double number = 0.0;
    std::string str;
    std::vector<Value> items;                                  // array
    std::vector<std::pair<std::string, Value>> members;        // object
};

class Parser {
public:
    explicit Parser(const std::string& text) : text_(text) {}

    bool parse(Value& out, std::string& error) {
        skipWs();
        if (!parseValue(out)) {
            error = "JSON parse error at offset " + std::to_string(pos_) + ": " + err_;
            return false;
        }
        skipWs();
        if (pos_ != text_.size()) {
            error = "JSON trailing characters at offset " + std::to_string(pos_);
            return false;
        }
        return true;
    }

private:
    const std::string& text_;
    size_t pos_ = 0;
    std::string err_;

    bool fail(const std::string& msg) {
        err_ = msg;
        return false;
    }

    void skipWs() {
        while (pos_ < text_.size() &&
               (text_[pos_] == ' ' || text_[pos_] == '\t' ||
                text_[pos_] == '\n' || text_[pos_] == '\r')) {
            pos_++;
        }
    }

    bool parseValue(Value& v) {
        if (pos_ >= text_.size()) {
            return fail("unexpected end of input");
        }
        char c = text_[pos_];
        if (c == '{') return parseObject(v);
        if (c == '[') return parseArray(v);
        if (c == '"') return parseString(v.str) && (v.type = Value::Type::String, true);
        if (c == 't') return parseKeyword("true", v, true);
        if (c == 'f') return parseKeyword("false", v, false);
        if (c == 'n') return parseKeyword("null", v);
        if (c == '-' || (c >= '0' && c <= '9')) return parseNumber(v);
        return fail(std::string("unexpected character '") + c + "'");
    }

    bool parseKeyword(const char* kw, Value& v, bool boolVal = false) {
        size_t len = std::char_traits<char>::length(kw);
        if (text_.compare(pos_, len, kw) != 0) {
            return fail(std::string("expected '") + kw + "'");
        }
        pos_ += len;
        v.type = (kw[0] == 'n') ? Value::Type::Null : Value::Type::Bool;
        v.boolean = boolVal;
        return true;
    }

    bool parseNumber(Value& v) {
        size_t start = pos_;
        if (pos_ < text_.size() && text_[pos_] == '-') pos_++;
        while (pos_ < text_.size() &&
               ((text_[pos_] >= '0' && text_[pos_] <= '9') ||
                text_[pos_] == '.' || text_[pos_] == 'e' ||
                text_[pos_] == 'E' || text_[pos_] == '+' || text_[pos_] == '-')) {
            pos_++;
        }
        if (pos_ == start) {
            return fail("invalid number");
        }
        v.type = Value::Type::Number;
        v.number = std::strtod(text_.substr(start, pos_ - start).c_str(), nullptr);
        return true;
    }

    bool parseString(std::string& out) {
        if (pos_ >= text_.size() || text_[pos_] != '"') {
            return fail("expected string");
        }
        pos_++;
        out.clear();
        while (pos_ < text_.size() && text_[pos_] != '"') {
            char c = text_[pos_++];
            if (c == '\\') {
                if (pos_ >= text_.size()) return fail("bad escape");
                char esc = text_[pos_++];
                switch (esc) {
                    case 'n': out += '\n'; break;
                    case 't': out += '\t'; break;
                    case 'r': out += '\r'; break;
                    case 'b': out += '\b'; break;
                    case 'f': out += '\f'; break;
                    case '"': out += '"'; break;
                    case '\\': out += '\\'; break;
                    case '/': out += '/'; break;
                    case 'u': {
                        if (pos_ + 4 > text_.size()) return fail("bad \\u escape");
                        std::string hex = text_.substr(pos_, 4);
                        unsigned int cp = static_cast<unsigned int>(strtoul(hex.c_str(), nullptr, 16));
                        pos_ += 4;
                        out += static_cast<char>(cp);  // BMP only, adequate for our data
                        break;
                    }
                    default: return fail("unknown escape");
                }
            } else {
                out += c;
            }
        }
        if (pos_ >= text_.size()) return fail("unterminated string");
        pos_++;  // closing quote
        return true;
    }

    bool parseArray(Value& v) {
        pos_++;  // '['
        v.type = Value::Type::Array;
        skipWs();
        if (pos_ < text_.size() && text_[pos_] == ']') {
            pos_++;
            return true;
        }
        while (true) {
            Value item;
            if (!parseValue(item)) return false;
            v.items.push_back(std::move(item));
            skipWs();
            if (pos_ >= text_.size()) return fail("unterminated array");
            char c = text_[pos_++];
            if (c == ']') return true;
            if (c != ',') return fail("expected ',' in array");
            skipWs();
        }
    }

    bool parseObject(Value& v) {
        pos_++;  // '{'
        v.type = Value::Type::Object;
        skipWs();
        if (pos_ < text_.size() && text_[pos_] == '}') {
            pos_++;
            return true;
        }
        while (true) {
            skipWs();
            std::string key;
            if (!parseString(key)) return false;
            skipWs();
            if (pos_ >= text_.size() || text_[pos_] != ':') {
                return fail("expected ':'");
            }
            pos_++;
            Value val;
            if (!parseValue(val)) return false;
            v.members.emplace_back(key, std::move(val));
            skipWs();
            if (pos_ >= text_.size()) return fail("unterminated object");
            char c = text_[pos_++];
            if (c == '}') return true;
            if (c != ',') return fail("expected ',' in object");
        }
    }
};

std::string escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\t': out += "\\t"; break;
            case '\r': out += "\\r"; break;
            default: out += c;
        }
    }
    return out;
}

std::string dumps(const Value& v, int indent = 0) {
    std::string pad;
    auto nl = [&]() {
        return indent > 0 ? "\n" + std::string(indent * 2, ' ') : " ";
    };
    auto nlOuter = [&]() {
        return indent > 0 ? "\n" + std::string((indent - 1) * 2, ' ') : "";
    };

    switch (v.type) {
        case Value::Type::Null:
            return "null";
        case Value::Type::Bool:
            return v.boolean ? "true" : "false";
        case Value::Type::Number: {
            std::ostringstream ss;
            ss << v.number;
            return ss.str();
        }
        case Value::Type::String:
            return "\"" + escape(v.str) + "\"";
        case Value::Type::Array: {
            if (v.items.empty()) return "[]";
            std::string out = "[";
            for (size_t i = 0; i < v.items.size(); i++) {
                if (i > 0) out += ",";
                out += nl() + dumps(v.items[i], indent > 0 ? indent + 1 : 1);
            }
            out += nlOuter() + "]";
            return out;
        }
        case Value::Type::Object: {
            if (v.members.empty()) return "{}";
            std::string out = "{";
            for (size_t i = 0; i < v.members.size(); i++) {
                if (i > 0) out += ",";
                out += nl() + "\"" + escape(v.members[i].first) + "\": " +
                       dumps(v.members[i].second, indent > 0 ? indent + 1 : 1);
            }
            out += nlOuter() + "}";
            return out;
        }
    }
    return "null";
}

} // namespace jsonlite

// ============================================================================
// RulesStore implementation
// ============================================================================

namespace {

bool isValidType(const std::string& type) {
    return type == "ip" || type == "app" || type == "domain" || type == "port";
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

} // namespace

bool RulesStore::load(const std::string& path, std::string& error) {
    std::ifstream file(path);
    if (!file.is_open()) {
        error = "Cannot open rules file: " + path;
        return false;
    }
    std::ostringstream buffer;
    buffer << file.rdbuf();
    std::string text = buffer.str();

    jsonlite::Value root;
    jsonlite::Parser parser(text);
    if (!parser.parse(root, error)) {
        return false;
    }
    if (root.type != jsonlite::Value::Type::Object) {
        error = "Rules file root must be a JSON object";
        return false;
    }

    rules_.clear();
    for (const auto& member : root.members) {
        if (member.first != "rules" ||
            member.second.type != jsonlite::Value::Type::Array) {
            continue;
        }
        for (const auto& item : member.second.items) {
            if (item.type != jsonlite::Value::Type::Object) continue;
            RuleEntry entry;
            for (const auto& field : item.members) {
                const std::string& k = field.first;
                const jsonlite::Value& v = field.second;
                if (k == "id" && v.type == jsonlite::Value::Type::Number) {
                    entry.id = static_cast<int64_t>(v.number);
                } else if (k == "type" && v.type == jsonlite::Value::Type::String) {
                    entry.type = v.str;
                } else if (k == "value" && v.type == jsonlite::Value::Type::String) {
                    entry.value = v.str;
                } else if (k == "enabled" && v.type == jsonlite::Value::Type::Bool) {
                    entry.enabled = v.boolean;
                } else if (k == "note" && v.type == jsonlite::Value::Type::String) {
                    entry.note = v.str;
                }
            }
            if (entry.type.empty() || entry.value.empty()) continue;
            if (entry.id >= next_id_) next_id_ = entry.id + 1;
            rules_.push_back(std::move(entry));
        }
    }

    std::cout << "[RulesStore] Loaded " << rules_.size() << " rules from " << path << std::endl;
    return true;
}

bool RulesStore::save(const std::string& path, std::string& error) const {
    jsonlite::Value root;
    root.type = jsonlite::Value::Type::Object;
    root.members.emplace_back("version",
        []() { jsonlite::Value v; v.type = jsonlite::Value::Type::Number; v.number = 1; return v; }());
    root.members.emplace_back("rules", jsonlite::Value());

    jsonlite::Value& arr = root.members.back().second;
    arr.type = jsonlite::Value::Type::Array;
    for (const auto& r : rules_) {
        jsonlite::Value obj;
        obj.type = jsonlite::Value::Type::Object;

        jsonlite::Value id; id.type = jsonlite::Value::Type::Number; id.number = static_cast<double>(r.id);
        obj.members.emplace_back("id", std::move(id));

        jsonlite::Value type; type.type = jsonlite::Value::Type::String; type.str = r.type;
        obj.members.emplace_back("type", std::move(type));

        jsonlite::Value val; val.type = jsonlite::Value::Type::String; val.str = r.value;
        obj.members.emplace_back("value", std::move(val));

        jsonlite::Value en; en.type = jsonlite::Value::Type::Bool; en.boolean = r.enabled;
        obj.members.emplace_back("enabled", std::move(en));

        jsonlite::Value note; note.type = jsonlite::Value::Type::String; note.str = r.note;
        obj.members.emplace_back("note", std::move(note));

        arr.items.push_back(std::move(obj));
    }

    std::ofstream file(path);
    if (!file.is_open()) {
        error = "Cannot open rules file for writing: " + path;
        return false;
    }
    file << jsonlite::dumps(root, 1) << "\n";
    file.close();

    std::cout << "[RulesStore] Saved " << rules_.size() << " rules to " << path << std::endl;
    return true;
}

int64_t RulesStore::addRule(const std::string& type,
                            const std::string& value,
                            bool enabled,
                            const std::string& note,
                            std::string& error) {
    std::string t = lower(type);
    if (!isValidType(t)) {
        error = "Invalid rule type '" + type + "' (expected ip, app, domain, port)";
        return -1;
    }
    if (value.empty()) {
        error = "Rule value cannot be empty";
        return -1;
    }

    RuleEntry entry;
    entry.id = next_id_++;
    entry.type = t;
    entry.value = value;
    entry.enabled = enabled;
    entry.note = note;
    rules_.push_back(entry);
    return entry.id;
}

bool RulesStore::deleteRule(int64_t id) {
    auto it = std::find_if(rules_.begin(), rules_.end(),
                           [id](const RuleEntry& e) { return e.id == id; });
    if (it == rules_.end()) {
        return false;
    }
    rules_.erase(it);
    return true;
}

bool RulesStore::setEnabled(int64_t id, bool enabled) {
    for (auto& e : rules_) {
        if (e.id == id) {
            e.enabled = enabled;
            return true;
        }
    }
    return false;
}

void RulesStore::clear() {
    rules_.clear();
    next_id_ = 1;
}

bool RulesStore::applyTo(RuleManager& rm, std::string& error) const {
    // Only allow IP / domain / port here; app values are validated by name.
    for (const auto& r : rules_) {
        if (!r.enabled) continue;
        if (r.type == "ip") {
            rm.blockIP(r.value);
        } else if (r.type == "domain") {
            rm.blockDomain(r.value);
        } else if (r.type == "port") {
            char* end = nullptr;
            long port = std::strtol(r.value.c_str(), &end, 10);
            if (end == r.value.c_str() || port < 0 || port > 65535) {
                error = "Invalid port value in rule '" + r.value + "'";
                return false;
            }
            rm.blockPort(static_cast<uint16_t>(port));
        } else if (r.type == "app") {
            bool found = false;
            for (int i = 1; i < static_cast<int>(AppType::APP_COUNT); i++) {
                if (appTypeToString(static_cast<AppType>(i)) == r.value) {
                    rm.blockApp(static_cast<AppType>(i));
                    found = true;
                    break;
                }
            }
            if (!found) {
                error = "Unknown app value in rule '" + r.value + "'";
                return false;
            }
        }
    }
    return true;
}

} // namespace DPI