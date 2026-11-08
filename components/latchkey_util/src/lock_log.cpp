// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/lock_log.h"

#include <cstdio>

#include "latchkey_util/lock_time.h"

namespace latchkey_util {

namespace {

void appendNumber(std::string& out, long long value) {
    char text[24];
    std::snprintf(text, sizeof(text), "%lld", value);
    out += text;
}

void appendEntry(std::string& out, const ttlock::LogEntry& entry, int32_t lockUtcOffsetSeconds) {
    out += "{\"seq\":";
    appendNumber(out, entry.recordNumber);
    out += ",\"time\":";
    int64_t local = 0;
    if (localSecondsOf(entry.time, local)) {
        appendNumber(out, local - lockUtcOffsetSeconds);
    } else {
        out += "null";
    }
    out += ",\"type\":";
    appendNumber(out, entry.type);
    out += ",\"battery\":";
    appendNumber(out, entry.battery);
    out += '}';
}

}

std::string logEntriesJson(const std::vector<ttlock::LogEntry>& entries, int32_t lockUtcOffsetSeconds) {
    std::string out = "[";
    for (size_t i = 0; i < entries.size(); ++i) {
        if (i > 0) {
            out += ',';
        }
        appendEntry(out, entries[i], lockUtcOffsetSeconds);
    }
    out += ']';
    return out;
}

}
