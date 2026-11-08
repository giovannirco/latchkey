// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/weekly_window.h"

#include <cstdio>

namespace latchkey_util {

namespace {

constexpr int kFirstWeekday = 1;
constexpr int kLastWeekday = 7;
constexpr uint8_t kAllWeekdays = 0x7F;
constexpr size_t kClockTimeLength = 5;

bool isDigit(char c) { return c >= '0' && c <= '9'; }

}

bool isWeeklyWindow(const WeeklyWindow& window) {
    return window.days != 0 && (window.days & ~kAllWeekdays) == 0 && window.startMinute < window.endMinute &&
           window.endMinute <= kMinutesPerDay;
}

bool parseClockTime(std::string_view text, uint16_t& minuteOfDay) {
    if (text.size() != kClockTimeLength || text[2] != ':' || !isDigit(text[0]) || !isDigit(text[1]) ||
        !isDigit(text[3]) || !isDigit(text[4])) {
        return false;
    }
    const int hour = (text[0] - '0') * 10 + (text[1] - '0');
    const int minute = (text[3] - '0') * 10 + (text[4] - '0');
    if (hour > 23 || minute > 59) {
        return false;
    }
    minuteOfDay = static_cast<uint16_t>(hour * 60 + minute);
    return true;
}

std::string formatClockTime(uint16_t minuteOfDay) {
    char text[8];
    std::snprintf(text, sizeof(text), "%02u:%02u", static_cast<unsigned>(minuteOfDay / 60),
                  static_cast<unsigned>(minuteOfDay % 60));
    return text;
}

bool addWeekday(int day, uint8_t& days) {
    if (day < kFirstWeekday || day > kLastWeekday) {
        return false;
    }
    days = static_cast<uint8_t>(days | (1u << (day - kFirstWeekday)));
    return true;
}

std::vector<uint8_t> weekdays(uint8_t days) {
    std::vector<uint8_t> out;
    for (int day = kFirstWeekday; day <= kLastWeekday; ++day) {
        if ((days & (1u << (day - kFirstWeekday))) != 0) {
            out.push_back(static_cast<uint8_t>(day));
        }
    }
    return out;
}

std::vector<ttlock::WeeklyCycle> weeklyCycles(const WeeklyWindow& window) {
    std::vector<ttlock::WeeklyCycle> cycles;
    if (!isWeeklyWindow(window)) {
        return cycles;
    }
    for (uint8_t day : weekdays(window.days)) {
        cycles.push_back(ttlock::WeeklyCycle{day, window.startMinute, window.endMinute});
    }
    return cycles;
}

}
