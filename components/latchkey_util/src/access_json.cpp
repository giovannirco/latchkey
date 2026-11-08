// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/access_json.h"

#include <cstdio>

#include "latchkey_util/credential_id.h"

namespace latchkey_util {

namespace {

constexpr char kHexDigits[] = "0123456789abcdef";
constexpr size_t kPasscodeFixedBytes = 128;
constexpr size_t kCredentialFixedBytes = 160;
constexpr size_t kEscapedBytesPerNameByte = 2;
constexpr size_t kSeparatorBytes = 1;

void appendNumber(std::string& out, int64_t value) {
    char text[24];
    std::snprintf(text, sizeof(text), "%lld", static_cast<long long>(value));
    out += text;
}

void appendWindow(std::string& out, const std::optional<UtcWindow>& window) {
    if (!window.has_value()) {
        out += "null";
        return;
    }
    out += "{\"start\":";
    appendNumber(out, window->start);
    out += ",\"end\":";
    appendNumber(out, window->end);
    out += '}';
}

void appendCycle(std::string& out, const WeeklyWindow& cycle) {
    out += "{\"days\":[";
    bool first = true;
    for (uint8_t day : weekdays(cycle.days)) {
        if (!first) {
            out += ',';
        }
        first = false;
        appendNumber(out, day);
    }
    out += "],\"start\":";
    appendJsonString(out, formatClockTime(cycle.startMinute));
    out += ",\"end\":";
    appendJsonString(out, formatClockTime(cycle.endMinute));
    out += '}';
}

}

void appendJsonString(std::string& out, std::string_view value) {
    out += '"';
    for (const char c : value) {
        const auto byte = static_cast<unsigned char>(c);
        if (c == '"' || c == '\\') {
            out += '\\';
            out += c;
        } else if (c == '\n') {
            out += "\\n";
        } else if (byte < 0x20) {
            out += "\\u00";
            out += kHexDigits[byte >> 4];
            out += kHexDigits[byte & 0x0F];
        } else {
            out += c;
        }
    }
    out += '"';
}

void appendPasscodeJson(std::string& out, const PasscodeView& view) {
    out += "{\"id\":";
    appendJsonString(out, view.id);
    out += ",\"type\":";
    appendJsonString(out, view.type);
    out += ",\"name\":";
    appendJsonString(out, view.name);
    out += ",\"validity\":";
    appendWindow(out, view.window);
    out += ",\"managed\":";
    out += view.managed ? "true" : "false";
    if (!view.code.empty()) {
        out += ",\"code\":";
        appendJsonString(out, view.code);
    }
    out += '}';
}

void appendCredentialJson(std::string& out, const CredentialView& view) {
    out += "{\"id\":";
    appendJsonString(out, formatCredentialId(view.id));
    out += ",\"name\":";
    appendJsonString(out, view.name);
    out += ",\"validity\":";
    appendWindow(out, view.window);
    if (view.cycle.has_value()) {
        out += ",\"cycle\":";
        appendCycle(out, *view.cycle);
    }
    out += '}';
}

size_t passcodeJsonBound(size_t nameBytes) {
    return kPasscodeFixedBytes + kEscapedBytesPerNameByte * nameBytes + kSeparatorBytes;
}

size_t credentialJsonBound(size_t nameBytes) {
    return kCredentialFixedBytes + kEscapedBytesPerNameByte * nameBytes + kSeparatorBytes;
}

bool listFitsInHeap(size_t textBytes, size_t freeBytes, size_t largestBlock) {
    return kListCopies * textBytes + kListHeadroomBytes <= freeBytes && textBytes <= largestBlock;
}

}
