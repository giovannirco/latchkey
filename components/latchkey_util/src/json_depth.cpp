// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/json_depth.h"

namespace latchkey_util {

namespace {

bool isScalarChar(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '+' ||
           c == '.';
}

}

bool jsonNestingWithin(std::string_view text, size_t maxDepth) {
    size_t depth = 0;
    bool inString = false;
    bool escaped = false;
    for (const char c : text) {
        if (inString) {
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                inString = false;
            }
            continue;
        }
        if (c == '"') {
            inString = true;
        } else if (c == '[' || c == '{') {
            if (++depth > maxDepth) {
                return false;
            }
        } else if ((c == ']' || c == '}') && depth > 0) {
            --depth;
        }
    }
    return true;
}

bool jsonValuesWithin(std::string_view text, size_t maxValues) {
    size_t values = 0;
    bool inString = false;
    bool escaped = false;
    bool inScalar = false;
    for (const char c : text) {
        if (inString) {
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                inString = false;
            }
            continue;
        }
        if (isScalarChar(c)) {
            if (!inScalar && ++values > maxValues) {
                return false;
            }
            inScalar = true;
            continue;
        }
        inScalar = false;
        if (c == '"' || c == '[' || c == '{') {
            inString = c == '"';
            if (++values > maxValues) {
                return false;
            }
        }
    }
    return true;
}

}
