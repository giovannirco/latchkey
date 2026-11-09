// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/hostname.h"

namespace latchkey_util {

namespace {

bool isHostCharacter(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
}

}

bool isHostname(std::string_view host) {
    if (host.empty() || host.size() > kMaxHostname) {
        return false;
    }
    bool labelStart = true;
    for (char c : host) {
        if (c == '.') {
            if (labelStart) {
                return false;
            }
            labelStart = true;
            continue;
        }
        if (!isHostCharacter(c)) {
            return false;
        }
        labelStart = false;
    }
    return !labelStart;
}

}
