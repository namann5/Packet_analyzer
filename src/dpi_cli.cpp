#include "rules_store.h"

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

namespace {

constexpr const char* kDefaultStore = "rules.json";

void printUsage(const char* program) {
    std::cout <<
        "╔══════════════════════════════════════════════════════════════╗\n"
        "║                    DPI RULES CLI v1.0                        ║\n"
        "║              Persistent rule management tool                  ║\n"
        "╚══════════════════════════════════════════════════════════════╝\n\n"
        "Usage: " << program << " <command> [options]\n\n"
        "Commands:\n"
        "  add-rule --type <ip|app|domain|port> --value <V>\n"
        "           [--note \"...\"] [--disabled]\n"
        "  del-rule <id>\n"
        "  list-rules [--type <type>]\n"
        "  enable <id>\n"
        "  disable <id>\n"
        "  import <rules.json>\n"
        "  export <out.json>\n"
        "  clear\n"
        "  help\n\n"
        "Options:\n"
        "  --store <file>   Rule store file (default: " << kDefaultStore << ")\n\n";
}

// Minimal argv parser: returns values for the given flags.
std::string getArg(int argc, char** argv, int start, const std::string& flag,
                   const std::string& dflt = "") {
    for (int i = start; i + 1 < argc; i++) {
        if (flag == argv[i]) {
            return argv[i + 1];
        }
    }
    return dflt;
}

bool hasFlag(int argc, char** argv, int start, const std::string& flag) {
    for (int i = start; i < argc; i++) {
        if (flag == argv[i]) {
            return true;
        }
    }
    return false;
}

int listRules(const DPI::RulesStore& store, const std::string& filter) {
    const auto& rules = store.rules();
    std::cout << "\nID      Type     Enabled  Value                     Note\n";
    std::cout << "------  -------  -------  ------------------------  --------------------\n";
    for (const auto& r : rules) {
        if (!filter.empty() && r.type != filter) continue;
        std::cout << std::left
                  << std::setw(8) << r.id
                  << std::setw(9) << r.type
                  << std::setw(9) << (r.enabled ? "yes" : "no")
                  << std::setw(25) << r.value
                  << r.note << "\n";
    }
    std::cout << "------\n" << rules.size() << " rule(s)\n\n";
    return 0;
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    std::string command = argv[1];
    if (command == "help" || command == "-h" || command == "--help") {
        printUsage(argv[0]);
        return 0;
    }

    std::string store_path = getArg(argc, argv, 2, "--store", kDefaultStore);

    DPI::RulesStore store;
    std::string error;

    // Most commands operate on an existing store; add-rule also loads it.
    if (!store.load(store_path, error)) {
        if (command != "add-rule") {
            // Missing store is only an error for read/delete commands.
            if (command != "export" && command != "clear" && command != "del-rule" &&
                command != "enable" && command != "disable") {
                std::cerr << "[dpi_cli] " << error << "\n";
                return 1;
            }
        }
    }

    int rc = 0;

    if (command == "add-rule") {
        std::string type = getArg(argc, argv, 2, "--type");
        std::string value = getArg(argc, argv, 2, "--value");
        std::string note = getArg(argc, argv, 2, "--note");
        bool enabled = !hasFlag(argc, argv, 2, "--disabled");

        if (type.empty() || value.empty()) {
            std::cerr << "add-rule requires --type and --value\n";
            return 1;
        }

        int64_t id = store.addRule(type, value, enabled, note, error);
        if (id < 0) {
            std::cerr << "[dpi_cli] " << error << "\n";
            return 1;
        }
        if (!store.save(store_path, error)) {
            std::cerr << "[dpi_cli] " << error << "\n";
            return 1;
        }
        std::cout << "Added rule id=" << id << " type=" << type
                  << " value=" << value << "\n";
    } else if (command == "del-rule") {
        if (argc < 3) {
            std::cerr << "del-rule requires an id\n";
            return 1;
        }
        int64_t id = std::atoll(argv[2]);
        if (!store.deleteRule(id)) {
            std::cerr << "Rule id " << id << " not found\n";
            return 1;
        }
        store.save(store_path, error);
        std::cout << "Deleted rule id=" << id << "\n";
    } else if (command == "list-rules") {
        std::string filter = getArg(argc, argv, 2, "--type");
        rc = listRules(store, filter);
    } else if (command == "enable" || command == "disable") {
        if (argc < 3) {
            std::cerr << command << " requires an id\n";
            return 1;
        }
        int64_t id = std::atoll(argv[2]);
        if (!store.setEnabled(id, command == "enable")) {
            std::cerr << "Rule id " << id << " not found\n";
            return 1;
        }
        store.save(store_path, error);
        std::cout << command << "d rule id=" << id << "\n";
    } else if (command == "import") {
        if (argc < 3) {
            std::cerr << "import requires a source file\n";
            return 1;
        }
        DPI::RulesStore src;
        if (!src.load(argv[2], error)) {
            std::cerr << "[dpi_cli] " << error << "\n";
            return 1;
        }
        // Replace current store contents with imported rules.
        store.clear();
        for (const auto& r : src.rules()) {
            store.addRule(r.type, r.value, r.enabled, r.note, error);
        }
        if (!store.save(store_path, error)) {
            std::cerr << "[dpi_cli] " << error << "\n";
            return 1;
        }
        std::cout << "Imported " << src.size() << " rules from " << argv[2] << "\n";
    } else if (command == "export") {
        if (argc < 3) {
            std::cerr << "export requires a destination file\n";
            return 1;
        }
        if (!store.save(argv[2], error)) {
            std::cerr << "[dpi_cli] " << error << "\n";
            return 1;
        }
    } else if (command == "clear") {
        store.clear();
        store.save(store_path, error);
        std::cout << "Cleared all rules in " << store_path << "\n";
    } else {
        std::cerr << "Unknown command: " << command << "\n";
        printUsage(argv[0]);
        return 1;
    }

    return rc;
}