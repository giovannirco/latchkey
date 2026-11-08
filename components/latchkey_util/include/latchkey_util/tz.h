// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace latchkey_util {

inline constexpr size_t kMaxTimeZoneLength = 64;

struct TransitionRule {
    enum class Kind : uint8_t {
        JulianNoLeap,
        ZeroBasedDay,
        MonthWeekDay,
    };

    Kind kind = Kind::MonthWeekDay;
    uint8_t month = 0;
    uint8_t week = 0;
    uint16_t day = 0;
    int32_t timeSeconds = 0;
};

struct TimeZone {
    int32_t standardOffset = 0;
    int32_t daylightOffset = 0;
    bool hasDaylight = false;
    TransitionRule start;
    TransitionRule end;
};

bool parseTimeZone(std::string_view text, TimeZone& out);

int32_t utcOffsetAt(const TimeZone& zone, int64_t utcSeconds);

std::string localTimestamp(int64_t utcSeconds, int32_t utcOffsetSeconds);

}
