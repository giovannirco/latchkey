// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/credential_id.h"

#include <charconv>
#include <system_error>

namespace latchkey_util {

bool parseCredentialId(std::string_view text, uint64_t maximum, uint64_t& out) {
    if (text.empty() || (text.size() > 1 && text[0] == '0')) {
        return false;
    }
    for (char c : text) {
        if (c < '0' || c > '9') {
            return false;
        }
    }
    uint64_t value = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc() || end != text.data() + text.size() || value > maximum) {
        return false;
    }
    out = value;
    return true;
}

std::string formatCredentialId(uint64_t id) { return std::to_string(id); }

}
