// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/secret_pattern.h"

#include <cstddef>

namespace latchkey_util {

namespace {

constexpr size_t kSecretRun = 32;
constexpr std::string_view kMarkers[] = {"otpauth://", "secret=", "lk_session="};
constexpr std::string_view kTextMembers[] = {"\"password\"", "\"totp\"",   "\"passphrase\"", "\"adminPasscode\"",
                                             "\"current\"",  "\"new\"",    "\"backup\"",     "\"otpauth\""};
constexpr std::string_view kDigitMember = "\"code\"";

char lower(char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c; }

bool containsIgnoringCase(std::string_view text, std::string_view needle) {
    for (size_t start = 0; start + needle.size() <= text.size(); ++start) {
        size_t matched = 0;
        while (matched < needle.size() && lower(text[start + matched]) == needle[matched]) {
            ++matched;
        }
        if (matched == needle.size()) {
            return true;
        }
    }
    return false;
}

bool isHex(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }

bool isBase32(char c) { return (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7'); }

template <typename Predicate>
bool hasRun(std::string_view text, Predicate inRun) {
    size_t run = 0;
    for (char c : text) {
        run = inRun(c) ? run + 1 : 0;
        if (run >= kSecretRun) {
            return true;
        }
    }
    return false;
}

size_t skipSpaces(std::string_view text, size_t position) {
    while (position < text.size() && text[position] == ' ') {
        ++position;
    }
    return position;
}

bool hasStringMember(std::string_view text, std::string_view key, bool digits) {
    for (size_t found = text.find(key); found != std::string_view::npos; found = text.find(key, found + 1)) {
        size_t position = skipSpaces(text, found + key.size());
        if (position >= text.size() || text[position] != ':') {
            continue;
        }
        position = skipSpaces(text, position + 1);
        if (position >= text.size() || text[position] != '"') {
            continue;
        }
        const bool digit = position + 1 < text.size() && text[position + 1] >= '0' && text[position + 1] <= '9';
        if (!digits || digit) {
            return true;
        }
    }
    return false;
}

}

bool holdsSecretPattern(std::string_view text) {
    for (std::string_view marker : kMarkers) {
        if (containsIgnoringCase(text, marker)) {
            return true;
        }
    }
    for (std::string_view key : kTextMembers) {
        if (hasStringMember(text, key, false)) {
            return true;
        }
    }
    return hasStringMember(text, kDigitMember, true) || hasRun(text, isHex) || hasRun(text, isBase32);
}

}
