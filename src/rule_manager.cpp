#include "rule_manager.h"

#include <sstream>
#include <iostream>
#include <algorithm>
#include <mutex>
#include <fstream>
#include <regex>
#include <cctype>

namespace DPI {

// ============================================================================
// Helper Functions
// ============================================================================

namespace {

std::string trim(const std::string& value) {

    size_t start = 0;

    while (start < value.size() &&
           std::isspace(
               static_cast<unsigned char>(value[start])
           )) {
        start++;
    }

    size_t end = value.size();

    while (end > start &&
           std::isspace(
               static_cast<unsigned char>(value[end - 1])
           )) {
        end--;
    }

    return value.substr(start, end - start);
}


std::string toUpper(std::string value) {

    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char c) {
            return static_cast<char>(
                std::toupper(c)
            );
        }
    );

    return value;
}


std::string toLower(std::string value) {

    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char c) {
            return static_cast<char>(
                std::tolower(c)
            );
        }
    );

    return value;
}


// Extract a simple JSON string field.
//
// Example:
//
// "type": "IP"
// "value": "192.168.1.50"
//
std::string getJsonString(
    const std::string& object,
    const std::string& field
) {

    std::string pattern =
        "\"" + field +
        "\"\\s*:\\s*\"([^\"]*)\"";

    std::regex expression(pattern);

    std::smatch match;

    if (std::regex_search(
            object,
            match,
            expression
        )) {

        if (match.size() >= 2) {
            return match[1].str();
        }
    }

    return "";
}

} // anonymous namespace


// ============================================================================
// IP Blocking
// ============================================================================

uint32_t RuleManager::parseIP(
    const std::string& ip
) {

    uint32_t result = 0;

    int octet = 0;
    int shift = 0;

    for (char c : ip) {

        if (c == '.') {

            result |= (
                static_cast<uint32_t>(octet)
                << shift
            );

            shift += 8;
            octet = 0;

        } else if (c >= '0' && c <= '9') {

            octet =
                octet * 10
                + (c - '0');
        }
    }

    result |= (
        static_cast<uint32_t>(octet)
        << shift
    );

    return result;
}


std::string RuleManager::ipToString(
    uint32_t ip
) {

    std::ostringstream ss;

    ss
        << ((ip >> 0) & 0xFF) << "."
        << ((ip >> 8) & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "."
        << ((ip >> 24) & 0xFF);

    return ss.str();
}


void RuleManager::blockIP(
    uint32_t ip
) {

    std::unique_lock<std::shared_mutex> lock(
        ip_mutex_
    );

    blocked_ips_.insert(ip);

    std::cout
        << "[RuleManager] Blocked IP: "
        << ipToString(ip)
        << std::endl;
}


void RuleManager::blockIP(
    const std::string& ip
) {

    blockIP(parseIP(ip));
}


void RuleManager::unblockIP(
    uint32_t ip
) {

    std::unique_lock<std::shared_mutex> lock(
        ip_mutex_
    );

    blocked_ips_.erase(ip);

    std::cout
        << "[RuleManager] Unblocked IP: "
        << ipToString(ip)
        << std::endl;
}


void RuleManager::unblockIP(
    const std::string& ip
) {

    unblockIP(parseIP(ip));
}


bool RuleManager::isIPBlocked(
    uint32_t ip
) const {

    std::shared_lock<std::shared_mutex> lock(
        ip_mutex_
    );

    return blocked_ips_.count(ip) > 0;
}


std::vector<std::string>
RuleManager::getBlockedIPs() const {

    std::shared_lock<std::shared_mutex> lock(
        ip_mutex_
    );

    std::vector<std::string> result;

    for (uint32_t ip : blocked_ips_) {

        result.push_back(
            ipToString(ip)
        );
    }

    return result;
}


// ============================================================================
// Application Blocking
// ============================================================================

void RuleManager::blockApp(
    AppType app
) {

    std::unique_lock<std::shared_mutex> lock(
        app_mutex_
    );

    blocked_apps_.insert(app);

    std::cout
        << "[RuleManager] Blocked app: "
        << appTypeToString(app)
        << std::endl;
}


void RuleManager::unblockApp(
    AppType app
) {

    std::unique_lock<std::shared_mutex> lock(
        app_mutex_
    );

    blocked_apps_.erase(app);

    std::cout
        << "[RuleManager] Unblocked app: "
        << appTypeToString(app)
        << std::endl;
}


bool RuleManager::isAppBlocked(
    AppType app
) const {

    std::shared_lock<std::shared_mutex> lock(
        app_mutex_
    );

    return blocked_apps_.count(app) > 0;
}


std::vector<AppType>
RuleManager::getBlockedApps() const {

    std::shared_lock<std::shared_mutex> lock(
        app_mutex_
    );

    return std::vector<AppType>(
        blocked_apps_.begin(),
        blocked_apps_.end()
    );
}


// ============================================================================
// Domain Blocking
// ============================================================================

void RuleManager::blockDomain(
    const std::string& domain
) {

    std::unique_lock<std::shared_mutex> lock(
        domain_mutex_
    );

    if (domain.find('*') != std::string::npos) {

        domain_patterns_.push_back(domain);

    } else {

        blocked_domains_.insert(domain);
    }

    std::cout
        << "[RuleManager] Blocked domain: "
        << domain
        << std::endl;
}


void RuleManager::unblockDomain(
    const std::string& domain
) {

    std::unique_lock<std::shared_mutex> lock(
        domain_mutex_
    );

    if (domain.find('*') != std::string::npos) {

        auto it = std::find(
            domain_patterns_.begin(),
            domain_patterns_.end(),
            domain
        );

        if (it != domain_patterns_.end()) {

            domain_patterns_.erase(it);
        }

    } else {

        blocked_domains_.erase(domain);
    }

    std::cout
        << "[RuleManager] Unblocked domain: "
        << domain
        << std::endl;
}


bool RuleManager::domainMatchesPattern(
    const std::string& domain,
    const std::string& pattern
) {

    // Handle *.example.com

    if (
        pattern.size() >= 2 &&
        pattern[0] == '*' &&
        pattern[1] == '.'
    ) {

        std::string suffix =
            pattern.substr(1);

        // Check suffix

        if (
            domain.size() >= suffix.size() &&
            domain.compare(
                domain.size() - suffix.size(),
                suffix.size(),
                suffix
            ) == 0
        ) {

            return true;
        }

        // Also match bare domain

        if (
            domain ==
            pattern.substr(2)
        ) {

            return true;
        }
    }

    return false;
}


bool RuleManager::isDomainBlocked(
    const std::string& domain
) const {

    std::shared_lock<std::shared_mutex> lock(
        domain_mutex_
    );

    // Exact match

    if (
        blocked_domains_.count(domain) > 0
    ) {

        return true;
    }

    // Convert domain to lowercase

    std::string lower_domain =
        toLower(domain);

    for (
        const auto& pattern :
        domain_patterns_
    ) {

        std::string lower_pattern =
            toLower(pattern);

        if (
            domainMatchesPattern(
                lower_domain,
                lower_pattern
            )
        ) {

            return true;
        }
    }

    return false;
}


std::vector<std::string>
RuleManager::getBlockedDomains() const {

    std::shared_lock<std::shared_mutex> lock(
        domain_mutex_
    );

    std::vector<std::string> result(
        blocked_domains_.begin(),
        blocked_domains_.end()
    );

    result.insert(
        result.end(),
        domain_patterns_.begin(),
        domain_patterns_.end()
    );

    return result;
}


// ============================================================================
// Port Blocking
// ============================================================================

void RuleManager::blockPort(
    uint16_t port
) {

    std::unique_lock<std::shared_mutex> lock(
        port_mutex_
    );

    blocked_ports_.insert(port);

    std::cout
        << "[RuleManager] Blocked port: "
        << port
        << std::endl;
}


void RuleManager::unblockPort(
    uint16_t port
) {

    std::unique_lock<std::shared_mutex> lock(
        port_mutex_
    );

    blocked_ports_.erase(port);
}


bool RuleManager::isPortBlocked(
    uint16_t port
) const {

    std::shared_lock<std::shared_mutex> lock(
        port_mutex_
    );

    return blocked_ports_.count(port) > 0;
}


// ============================================================================
// Combined Check
// ============================================================================

std::optional<RuleManager::BlockReason>
RuleManager::shouldBlock(
    uint32_t src_ip,
    uint16_t dst_port,
    AppType app,
    const std::string& domain
) const {

    // Check IP first

    if (isIPBlocked(src_ip)) {

        return BlockReason{
            BlockReason::IP,
            ipToString(src_ip)
        };
    }


    // Check port

    if (isPortBlocked(dst_port)) {

        return BlockReason{
            BlockReason::PORT,
            std::to_string(dst_port)
        };
    }


    // Check application

    if (isAppBlocked(app)) {

        return BlockReason{
            BlockReason::APP,
            appTypeToString(app)
        };
    }


    // Check domain

    if (
        !domain.empty() &&
        isDomainBlocked(domain)
    ) {

        return BlockReason{
            BlockReason::DOMAIN,
            domain
        };
    }


    return std::nullopt;
}


// ============================================================================
// Persistence
// ============================================================================

bool RuleManager::saveRules(
    const std::string& filename
) const {

    std::ofstream file(filename);

    if (!file.is_open()) {

        return false;
    }


    // Save blocked IPs

    file << "[BLOCKED_IPS]\n";

    for (
        const auto& ip :
        getBlockedIPs()
    ) {

        file << ip << "\n";
    }


    // Save blocked apps

    file << "\n[BLOCKED_APPS]\n";

    for (
        const auto& app :
        getBlockedApps()
    ) {

        file
            << appTypeToString(app)
            << "\n";
    }


    // Save blocked domains

    file << "\n[BLOCKED_DOMAINS]\n";

    for (
        const auto& domain :
        getBlockedDomains()
    ) {

        file << domain << "\n";
    }


    // Save blocked ports

    file << "\n[BLOCKED_PORTS]\n";

    {
        std::shared_lock<std::shared_mutex> lock(
            port_mutex_
        );

        for (
            uint16_t port :
            blocked_ports_
        ) {

            file << port << "\n";
        }
    }


    file.close();

    std::cout
        << "[RuleManager] Rules saved to: "
        << filename
        << std::endl;

    return true;
}


// ============================================================================
// Load Rules
//
// Supports BOTH:
//
// 1. Existing RuleManager format:
//
// [BLOCKED_IPS]
// 192.168.1.50
//
// [BLOCKED_DOMAINS]
// *.youtube.com
//
// 2. FastAPI rules.json:
//
// [
//     {
//         "id": 1,
//         "type": "IP",
//         "value": "192.168.1.50",
//         "action": "BLOCK",
//         "status": "Active"
//     }
// ]
//
// ============================================================================

bool RuleManager::loadRules(
    const std::string& filename
) {

    std::ifstream file(filename);

    if (!file.is_open()) {

        std::cout
            << "[RuleManager] Could not open rules file: "
            << filename
            << std::endl;

        return false;
    }


    // Read complete file

    std::stringstream buffer;

    buffer << file.rdbuf();

    file.close();

    std::string content =
        buffer.str();


    // ========================================================
    // Detect JSON format
    // ========================================================

    std::string trimmed =
        trim(content);


    if (
        !trimmed.empty() &&
        trimmed[0] == '['
    ) {

        std::cout
            << "[RuleManager] JSON rules detected."
            << std::endl;


        // Find JSON objects

        std::regex object_regex(
            R"(\{[^{}]*\})"
        );

        auto begin =
            std::sregex_iterator(
                content.begin(),
                content.end(),
                object_regex
            );

        auto end =
            std::sregex_iterator();


        int loaded_rules = 0;


        for (
            auto it = begin;
            it != end;
            ++it
        ) {

            std::string object =
                it->str();


            std::string type =
                getJsonString(
                    object,
                    "type"
                );


            std::string value =
                getJsonString(
                    object,
                    "value"
                );


            std::string status =
                getJsonString(
                    object,
                    "status"
                );


            std::string action =
                getJsonString(
                    object,
                    "action"
                );


            type =
                toUpper(
                    trim(type)
                );


            status =
                toLower(
                    trim(status)
                );


            action =
                toUpper(
                    trim(action)
                );


            // Ignore invalid rules

            if (
                type.empty() ||
                value.empty()
            ) {

                continue;
            }


            // Only active BLOCK rules

            if (
                status == "DISABLED"
            ) {

                continue;
            }


            if (
                !action.empty() &&
                action != "BLOCK"
            ) {

                continue;
            }


            // =================================================
            // IP
            // =================================================

            if (type == "IP") {

                blockIP(value);

                loaded_rules++;

                continue;
            }


            // =================================================
            // DOMAIN
            // =================================================

            if (type == "DOMAIN") {

                blockDomain(value);

                loaded_rules++;

                continue;
            }


            // =================================================
            // PORT
            // =================================================

            if (type == "PORT") {

                try {

                    int port =
                        std::stoi(value);

                    if (
                        port >= 0 &&
                        port <= 65535
                    ) {

                        blockPort(
                            static_cast<uint16_t>(
                                port
                            )
                        );

                        loaded_rules++;
                    }

                } catch (...) {

                    std::cout
                        << "[RuleManager] Invalid port rule: "
                        << value
                        << std::endl;
                }

                continue;
            }


            // =================================================
            // APPLICATION
            // =================================================

            if (type == "APPLICATION") {

                bool found = false;


                for (
                    int i = 0;
                    i <
                    static_cast<int>(
                        AppType::APP_COUNT
                    );
                    i++
                ) {

                    AppType app =
                        static_cast<AppType>(i);

                    std::string app_name =
                        appTypeToString(app);


                    if (
                        toLower(app_name)
                        ==
                        toLower(value)
                    ) {

                        blockApp(app);

                        loaded_rules++;

                        found = true;

                        break;
                    }
                }


                if (!found) {

                    std::cout
                        << "[RuleManager] Unknown application rule: "
                        << value
                        << std::endl;
                }

                continue;
            }
        }


        std::cout
            << "[RuleManager] Loaded "
            << loaded_rules
            << " JSON rule(s) from: "
            << filename
            << std::endl;


        return true;
    }


    // ========================================================
    // Existing RuleManager format
    // ========================================================

    std::cout
        << "[RuleManager] Legacy rule format detected."
        << std::endl;


    std::istringstream input(
        content
    );

    std::string line;

    std::string current_section;


    while (
        std::getline(
            input,
            line
        )
    ) {

        line =
            trim(line);


        // Skip empty lines

        if (line.empty()) {

            continue;
        }


        // Skip comments

        if (
            line[0] == '#'
        ) {

            continue;
        }


        // Section headers

        if (
            line[0] == '['
        ) {

            current_section =
                line;

            continue;
        }


        // =====================================================
        // BLOCKED IPs
        // =====================================================

        if (
            current_section ==
            "[BLOCKED_IPS]"
        ) {

            blockIP(line);
        }


        // =====================================================
        // BLOCKED Apps
        // =====================================================

        else if (
            current_section ==
            "[BLOCKED_APPS]"
        ) {

            for (
                int i = 0;
                i <
                static_cast<int>(
                    AppType::APP_COUNT
                );
                i++
            ) {

                AppType app =
                    static_cast<AppType>(i);


                if (
                    appTypeToString(app)
                    ==
                    line
                ) {

                    blockApp(app);

                    break;
                }
            }
        }


        // =====================================================
        // BLOCKED Domains
        // =====================================================

        else if (
            current_section ==
            "[BLOCKED_DOMAINS]"
        ) {

            blockDomain(line);
        }


        // =====================================================
        // BLOCKED Ports
        // =====================================================

        else if (
            current_section ==
            "[BLOCKED_PORTS]"
        ) {

            try {

                int port =
                    std::stoi(line);

                if (
                    port >= 0 &&
                    port <= 65535
                ) {

                    blockPort(
                        static_cast<uint16_t>(
                            port
                        )
                    );
                }

            } catch (...) {

                std::cout
                    << "[RuleManager] Invalid port: "
                    << line
                    << std::endl;
            }
        }
    }


    std::cout
        << "[RuleManager] Rules loaded from: "
        << filename
        << std::endl;


    return true;
}


// ============================================================================
// Clear All Rules
// ============================================================================

void RuleManager::clearAll() {

    {
        std::unique_lock<std::shared_mutex> lock(
            ip_mutex_
        );

        blocked_ips_.clear();
    }


    {
        std::unique_lock<std::shared_mutex> lock(
            app_mutex_
        );

        blocked_apps_.clear();
    }


    {
        std::unique_lock<std::shared_mutex> lock(
            domain_mutex_
        );

        blocked_domains_.clear();

        domain_patterns_.clear();
    }


    {
        std::unique_lock<std::shared_mutex> lock(
            port_mutex_
        );

        blocked_ports_.clear();
    }


    std::cout
        << "[RuleManager] All rules cleared"
        << std::endl;
}


// ============================================================================
// Statistics
// ============================================================================

RuleManager::RuleStats
RuleManager::getStats() const {

    RuleStats stats;


    {
        std::shared_lock<std::shared_mutex> lock(
            ip_mutex_
        );

        stats.blocked_ips =
            blocked_ips_.size();
    }


    {
        std::shared_lock<std::shared_mutex> lock(
            app_mutex_
        );

        stats.blocked_apps =
            blocked_apps_.size();
    }


    {
        std::shared_lock<std::shared_mutex> lock(
            domain_mutex_
        );

        stats.blocked_domains =
            blocked_domains_.size()
            +
            domain_patterns_.size();
    }


    {
        std::shared_lock<std::shared_mutex> lock(
            port_mutex_
        );

        stats.blocked_ports =
            blocked_ports_.size();
    }


    return stats;
}


} // namespace DPI