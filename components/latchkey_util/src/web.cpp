// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/web.h"

#include <cstddef>

#include "latchkey_util/ipv4.h"

namespace latchkey_util {

namespace {

constexpr std::string_view kHttps = "https://";
constexpr std::string_view kDefaultPort = "443";
constexpr size_t kMaxHostName = 253;
constexpr size_t kMaxPortDigits = 5;

struct Authority {
    std::string_view name;
    std::string_view port;
};

char lower(char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c; }

bool equalsIgnoringCase(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (lower(a[i]) != lower(b[i])) {
            return false;
        }
    }
    return true;
}

std::string_view trim(std::string_view text) {
    const size_t first = text.find_first_not_of(" \t");
    if (first == std::string_view::npos) {
        return {};
    }
    return text.substr(first, text.find_last_not_of(" \t") - first + 1);
}

bool isHostChar(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-';
}

bool isDigits(std::string_view text) {
    for (char c : text) {
        if (c < '0' || c > '9') {
            return false;
        }
    }
    return true;
}

bool splitAuthority(std::string_view text, Authority& out) {
    const size_t colon = text.find(':');
    const std::string_view name = text.substr(0, colon);
    if (name.empty() || name.size() > kMaxHostName) {
        return false;
    }
    for (char c : name) {
        if (!isHostChar(c)) {
            return false;
        }
    }
    std::string_view port;
    if (colon != std::string_view::npos) {
        port = text.substr(colon + 1);
        if (port.empty() || port.size() > kMaxPortDigits || !isDigits(port)) {
            return false;
        }
    }
    out = Authority{name, port};
    return true;
}

std::string_view effectivePort(std::string_view port) { return port.empty() ? kDefaultPort : port; }

bool hasMediaType(std::string_view value, std::string_view type) {
    const std::string_view trimmed = trim(value);
    return equalsIgnoringCase(trim(trimmed.substr(0, trimmed.find(';'))), type);
}

}

bool isJsonContentType(std::string_view value) { return hasMediaType(value, "application/json"); }

bool isOctetStreamContentType(std::string_view value) { return hasMediaType(value, "application/octet-stream"); }

bool isOwnHost(std::string_view host, uint32_t address) {
    Authority authority;
    uint32_t named = 0;
    return address != 0 && splitAuthority(host, authority) && effectivePort(authority.port) == kDefaultPort &&
           parseIpv4(authority.name, named) && named == address;
}

bool isOwnOrigin(std::string_view origin, uint32_t address) {
    return origin.size() > kHttps.size() && equalsIgnoringCase(origin.substr(0, kHttps.size()), kHttps) &&
           isOwnHost(origin.substr(kHttps.size()), address);
}

std::optional<std::string> httpsRedirect(std::string_view host) {
    Authority authority;
    if (!splitAuthority(host, authority)) {
        return std::nullopt;
    }
    return std::string(kHttps) + std::string(authority.name) + "/";
}

std::string sessionCookie(std::string_view token) {
    return std::string(kSessionCookieName) + "=" + std::string(token) + "; Path=/; Secure; HttpOnly; SameSite=Strict";
}

}
