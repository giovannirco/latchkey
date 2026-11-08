// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "ttlock/types.h"

namespace latchkey_util {

inline constexpr uint16_t kMinutesPerDay = 24 * 60;

struct WeeklyWindow {
    uint8_t days = 0;
    uint16_t startMinute = 0;
    uint16_t endMinute = 0;

    bool operator==(const WeeklyWindow&) const = default;
};

bool isWeeklyWindow(const WeeklyWindow& window);

bool parseClockTime(std::string_view text, uint16_t& minuteOfDay);

std::string formatClockTime(uint16_t minuteOfDay);

bool addWeekday(int day, uint8_t& days);

std::vector<uint8_t> weekdays(uint8_t days);

std::vector<ttlock::WeeklyCycle> weeklyCycles(const WeeklyWindow& window);

}
