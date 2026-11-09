// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/syslog.h"

#include <cstdio>

#include "latchkey_util/tz.h"

namespace latchkey_util {

namespace {

constexpr unsigned kFacilityLocal0 = 16;
constexpr size_t kMaxHostnameField = 255;
constexpr size_t kMaxMessageIdField = 32;
constexpr uint32_t kMaxSequenceId = 2147483647;
constexpr size_t kDateAndTimeLength = 19;
constexpr char kEllipsis[] = "...";
constexpr size_t kEllipsisLength = sizeof(kEllipsis) - 1;

bool isPrintableAscii(char c) {
    const auto byte = static_cast<unsigned char>(c);
    return byte >= 33 && byte <= 126;
}

void appendField(std::string& out, std::string_view text, size_t maxLength) {
    if (text.empty()) {
        out += '-';
        return;
    }
    for (char c : text.substr(0, maxLength)) {
        out += isPrintableAscii(c) ? c : '_';
    }
}

void appendTimestamp(std::string& out, int64_t utcMs) {
    const int64_t seconds = utcMs >= 0 ? utcMs / 1000 : (utcMs - 999) / 1000;
    const int64_t millis = utcMs - seconds * 1000;
    out += localTimestamp(seconds, 0).substr(0, kDateAndTimeLength);
    char fraction[8];
    std::snprintf(fraction, sizeof(fraction), ".%03dZ", static_cast<int>(millis));
    out += fraction;
}

uint32_t sequenceId(uint32_t seq) { return seq == 0 ? kMaxSequenceId : (seq - 1) % kMaxSequenceId + 1; }

}

uint8_t syslogSeverity(LogLevel level) {
    switch (level) {
        case LogLevel::Error:
            return 3;
        case LogLevel::Warn:
            return 4;
        case LogLevel::Info:
            return 6;
        case LogLevel::Debug:
        case LogLevel::Verbose:
            return 7;
    }
    return 6;
}

void formatSyslog(std::string& out, const SyslogMessage& message, size_t maxBytes) {
    out.clear();
    char number[80];
    std::snprintf(number, sizeof(number), "<%u>1 ", kFacilityLocal0 * 8 + syslogSeverity(message.level));
    out += number;
    if (message.utcMs.has_value()) {
        appendTimestamp(out, *message.utcMs);
    } else {
        out += '-';
    }
    out += ' ';
    appendField(out, message.hostname, kMaxHostnameField);
    out += ' ';
    appendField(out, message.appName, kMaxSyslogAppName);
    out += " - ";
    appendField(out, message.tag, kMaxMessageIdField);
    std::snprintf(number, sizeof(number), " [meta sequenceId=\"%lu\" sysUpTime=\"%llu\"] ",
                  static_cast<unsigned long>(sequenceId(message.seq)),
                  static_cast<unsigned long long>(message.uptimeMs / 10));
    out += number;
    if (message.message.empty()) {
        out += '-';
        return;
    }
    if (out.size() + message.message.size() <= maxBytes) {
        out += message.message;
        return;
    }
    const size_t room = maxBytes > out.size() + kEllipsisLength ? maxBytes - out.size() - kEllipsisLength : 0;
    out += message.message.substr(0, utf8Prefix(message.message, room));
    out += kEllipsis;
}

void frameOctetCounted(std::string& out, std::string_view message) {
    char length[16];
    std::snprintf(length, sizeof(length), "%u ", static_cast<unsigned>(message.size()));
    out.assign(length);
    out += message;
}

bool isSyslogAppName(std::string_view name) {
    if (name.empty() || name.size() > kMaxSyslogAppName) {
        return false;
    }
    for (char c : name) {
        if (!isPrintableAscii(c)) {
            return false;
        }
    }
    return true;
}

}
