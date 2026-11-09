// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/lock_settings.h"

#include <cstdio>

#include "latchkey_util/weekly_window.h"

namespace latchkey_util {

namespace {

constexpr int kEveryDay = 0;
constexpr int kLastWeekday = 7;
constexpr int kFirstMonthDay = 1;
constexpr int kLastMonthDay = 31;
constexpr uint16_t kMinutesPerHour = 60;

bool dayFits(ttlock::PassageType type, int day) {
    if (type == ttlock::PassageType::Weekly) {
        return day >= kEveryDay && day <= kLastWeekday;
    }
    return type == ttlock::PassageType::Monthly && day >= kFirstMonthDay && day <= kLastMonthDay;
}

void appendNumber(std::string& out, long long value) {
    char text[24];
    std::snprintf(text, sizeof(text), "%lld", value);
    out += text;
}

void appendClock(std::string& out, uint8_t hour, uint8_t minute) {
    char text[16];
    std::snprintf(text, sizeof(text), "\"%02u:%02u\"", static_cast<unsigned>(hour), static_cast<unsigned>(minute));
    out += text;
}

void appendPassage(std::string& out, const ttlock::PassageMode& mode) {
    const bool weekly = mode.type == ttlock::PassageType::Weekly;
    const bool monthly = mode.type == ttlock::PassageType::Monthly;
    out += "{\"type\":\"";
    out += weekly || monthly ? passageTypeName(mode.type) : "other";
    out += "\",\"day\":";
    appendNumber(out, mode.weekOrDay);
    if (monthly) {
        out += ",\"month\":";
        appendNumber(out, mode.month);
    }
    out += ",\"start\":";
    appendClock(out, mode.startHour, mode.startMinute);
    out += ",\"end\":";
    appendClock(out, mode.endHour, mode.endMinute);
    out += '}';
}

void appendRange(std::string& out, uint16_t value) {
    if (value == 0) {
        out += "null";
    } else {
        appendNumber(out, value);
    }
}

bool reportsRange(const ttlock::AutoLockSetting& range) { return range.minSeconds > 0 && range.maxSeconds > 0; }

}

bool passageTypeOf(std::string_view name, ttlock::PassageType& out) {
    if (name == "weekly") {
        out = ttlock::PassageType::Weekly;
        return true;
    }
    if (name == "monthly") {
        out = ttlock::PassageType::Monthly;
        return true;
    }
    return false;
}

const char* passageTypeName(ttlock::PassageType type) {
    return type == ttlock::PassageType::Monthly ? "monthly" : "weekly";
}

bool makePassage(ttlock::PassageType type, int day, std::string_view start, std::string_view end,
                 ttlock::PassageMode& out) {
    uint16_t from = 0;
    uint16_t until = 0;
    if (!dayFits(type, day) || !parseClockTime(start, from) || !parseClockTime(end, until)) {
        return false;
    }
    out = ttlock::PassageMode{type,
                              static_cast<uint8_t>(day),
                              0,
                              static_cast<uint8_t>(from / kMinutesPerHour),
                              static_cast<uint8_t>(from % kMinutesPerHour),
                              static_cast<uint8_t>(until / kMinutesPerHour),
                              static_cast<uint8_t>(until % kMinutesPerHour)};
    return true;
}

bool runsForward(const ttlock::PassageMode& mode) {
    const int from = mode.startHour * kMinutesPerHour + mode.startMinute;
    const int until = mode.endHour * kMinutesPerHour + mode.endMinute;
    return until > from;
}

std::string passageListJson(const std::vector<ttlock::PassageMode>& modes) {
    std::string out = "[";
    for (size_t i = 0; i < modes.size(); ++i) {
        if (i > 0) {
            out += ',';
        }
        appendPassage(out, modes[i]);
    }
    out += ']';
    return out;
}

bool autolockAllowed(uint32_t seconds, const ttlock::AutoLockSetting& range) {
    if (seconds == 0) {
        return true;
    }
    if (!reportsRange(range)) {
        return seconds <= kMaxAutolockSeconds;
    }
    return seconds >= range.minSeconds && seconds <= range.maxSeconds;
}

std::string autolockJson(const ttlock::AutoLockSetting& setting) {
    std::string out = "{\"seconds\":";
    appendNumber(out, setting.seconds);
    out += ",\"min\":";
    appendRange(out, reportsRange(setting) ? setting.minSeconds : 0);
    out += ",\"max\":";
    appendRange(out, reportsRange(setting) ? setting.maxSeconds : 0);
    out += '}';
    return out;
}

std::string passageAddStopped(std::string_view failure, size_t added) {
    std::string message(failure);
    if (added == 0) {
        return message;
    }
    message += "; " + std::to_string(added);
    message += added == 1 ? " passage window was added before that" : " passage windows were added before that";
    return message;
}

}
