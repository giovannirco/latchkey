// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/label.h"

#include <cstdint>

namespace latchkey_util {

namespace {

bool isSpace(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'; }

bool inRange(uint8_t byte, uint8_t low, uint8_t high) { return byte >= low && byte <= high; }

size_t sequenceLength(std::string_view text, size_t at) {
    const auto lead = static_cast<uint8_t>(text[at]);
    if (lead < 0x80) {
        return lead < 0x20 || lead == 0x7F ? 0 : 1;
    }
    uint8_t secondLow = 0x80;
    uint8_t secondHigh = 0xBF;
    size_t length = 0;
    if (inRange(lead, 0xC2, 0xDF)) {
        length = 2;
    } else if (inRange(lead, 0xE0, 0xEF)) {
        length = 3;
        secondLow = lead == 0xE0 ? 0xA0 : 0x80;
        secondHigh = lead == 0xED ? 0x9F : 0xBF;
    } else if (inRange(lead, 0xF0, 0xF4)) {
        length = 4;
        secondLow = lead == 0xF0 ? 0x90 : 0x80;
        secondHigh = lead == 0xF4 ? 0x8F : 0xBF;
    } else {
        return 0;
    }
    if (at + length > text.size() || !inRange(static_cast<uint8_t>(text[at + 1]), secondLow, secondHigh)) {
        return 0;
    }
    for (size_t i = 2; i < length; ++i) {
        if (!inRange(static_cast<uint8_t>(text[at + i]), 0x80, 0xBF)) {
            return 0;
        }
    }
    return length;
}

}

bool normalizeLabel(std::string_view input, size_t maxCodePoints, std::string& out) {
    size_t begin = 0;
    size_t end = input.size();
    while (begin < end && isSpace(input[begin])) {
        ++begin;
    }
    while (end > begin && isSpace(input[end - 1])) {
        --end;
    }
    const std::string_view label = input.substr(begin, end - begin);
    if (label.empty()) {
        return false;
    }
    size_t codePoints = 0;
    for (size_t at = 0; at < label.size();) {
        const size_t length = sequenceLength(label, at);
        if (length == 0 || ++codePoints > maxCodePoints) {
            return false;
        }
        at += length;
    }
    out.assign(label.data(), label.size());
    return true;
}

}
