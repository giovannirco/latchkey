// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/tz.h"

#include <cstdio>

namespace latchkey_util {

namespace {

constexpr int32_t kSecondsPerMinute = 60;
constexpr int32_t kSecondsPerHour = 3600;
constexpr int64_t kSecondsPerDay = 86400;
constexpr int32_t kOffsetLimitSeconds = 24 * 3600;
constexpr uint32_t kMaxOffsetSeconds = kOffsetLimitSeconds - 1;
constexpr uint32_t kMaxRuleSeconds = 167 * 3600;
constexpr int32_t kDefaultRuleTime = 2 * kSecondsPerHour;
constexpr size_t kMinNameLength = 3;
constexpr uint32_t kMaxJulianDay = 365;
constexpr uint32_t kFirstJulianLeapShift = 60;
constexpr int64_t kDaysPerWeek = 7;
constexpr int64_t kThursday = 4;

bool isDigit(char c) { return c >= '0' && c <= '9'; }

bool isAlpha(char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }

class Cursor {
public:
    explicit Cursor(std::string_view text) : text_(text) {}

    bool done() const { return position_ == text_.size(); }

    char current() const { return done() ? '\0' : text_[position_]; }

    bool accept(char c) {
        if (done() || text_[position_] != c) {
            return false;
        }
        ++position_;
        return true;
    }

    void advance() { ++position_; }

    bool number(uint32_t minDigits, uint32_t maxDigits, uint32_t& out) {
        uint32_t digits = 0;
        uint32_t value = 0;
        while (digits < maxDigits && isDigit(current())) {
            value = value * 10 + static_cast<uint32_t>(current() - '0');
            advance();
            ++digits;
        }
        if (digits < minDigits) {
            return false;
        }
        out = value;
        return true;
    }

private:
    std::string_view text_;
    size_t position_ = 0;
};

bool parseName(Cursor& cursor) {
    size_t length = 0;
    if (cursor.accept('<')) {
        while (isAlpha(cursor.current()) || isDigit(cursor.current()) || cursor.current() == '+' ||
               cursor.current() == '-') {
            cursor.advance();
            ++length;
        }
        return length >= kMinNameLength && cursor.accept('>');
    }
    while (isAlpha(cursor.current())) {
        cursor.advance();
        ++length;
    }
    return length >= kMinNameLength;
}

bool parseClock(Cursor& cursor, uint32_t maxHourDigits, uint32_t maxSeconds, bool wholeMinutes, int32_t& out) {
    int32_t sign = 1;
    if (cursor.accept('-')) {
        sign = -1;
    } else {
        cursor.accept('+');
    }
    uint32_t hours = 0;
    uint32_t minutes = 0;
    uint32_t seconds = 0;
    if (!cursor.number(1, maxHourDigits, hours)) {
        return false;
    }
    if (cursor.accept(':')) {
        if (!cursor.number(2, 2, minutes) || minutes >= 60) {
            return false;
        }
        if (cursor.accept(':') && (!cursor.number(2, 2, seconds) || seconds >= 60)) {
            return false;
        }
    }
    const uint32_t total = hours * kSecondsPerHour + minutes * kSecondsPerMinute + seconds;
    if (total > maxSeconds || (wholeMinutes && seconds != 0)) {
        return false;
    }
    out = sign * static_cast<int32_t>(total);
    return true;
}

bool parseRule(Cursor& cursor, TransitionRule& rule) {
    uint32_t value = 0;
    if (cursor.accept('J')) {
        if (!cursor.number(1, 3, value) || value < 1 || value > kMaxJulianDay) {
            return false;
        }
        rule.kind = TransitionRule::Kind::JulianNoLeap;
        rule.day = static_cast<uint16_t>(value);
    } else if (cursor.accept('M')) {
        uint32_t month = 0;
        uint32_t week = 0;
        uint32_t weekday = 0;
        const bool valid = cursor.number(1, 2, month) && month >= 1 && month <= 12 && cursor.accept('.') &&
                           cursor.number(1, 1, week) && week >= 1 && week <= 5 && cursor.accept('.') &&
                           cursor.number(1, 1, weekday) && weekday <= 6;
        if (!valid) {
            return false;
        }
        rule.kind = TransitionRule::Kind::MonthWeekDay;
        rule.month = static_cast<uint8_t>(month);
        rule.week = static_cast<uint8_t>(week);
        rule.day = static_cast<uint16_t>(weekday);
    } else {
        if (!cursor.number(1, 3, value) || value > kMaxJulianDay) {
            return false;
        }
        rule.kind = TransitionRule::Kind::ZeroBasedDay;
        rule.day = static_cast<uint16_t>(value);
    }
    rule.timeSeconds = kDefaultRuleTime;
    return !cursor.accept('/') || parseClock(cursor, 3, kMaxRuleSeconds, false, rule.timeSeconds);
}

int64_t floorDiv(int64_t value, int64_t divisor) {
    const int64_t quotient = value / divisor;
    return (value % divisor != 0 && (value < 0) != (divisor < 0)) ? quotient - 1 : quotient;
}

int64_t floorMod(int64_t value, int64_t divisor) { return value - floorDiv(value, divisor) * divisor; }

bool isLeap(int64_t year) { return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0; }

uint32_t daysInMonth(int64_t year, uint32_t month) {
    static constexpr uint8_t kDays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    return month == 2 && isLeap(year) ? 29 : kDays[month - 1];
}

int64_t daysFromCivil(int64_t year, uint32_t month, uint32_t day) {
    year -= month <= 2 ? 1 : 0;
    const int64_t era = floorDiv(year, 400);
    const uint32_t yearOfEra = static_cast<uint32_t>(year - era * 400);
    const uint32_t dayOfYear = (153 * (month > 2 ? month - 3 : month + 9) + 2) / 5 + day - 1;
    const uint32_t dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear;
    return era * 146097 + static_cast<int64_t>(dayOfEra) - 719468;
}

struct Civil {
    int64_t year;
    uint32_t month;
    uint32_t day;
};

Civil civilFromDays(int64_t days) {
    days += 719468;
    const int64_t era = floorDiv(days, 146097);
    const uint32_t dayOfEra = static_cast<uint32_t>(days - era * 146097);
    const uint32_t yearOfEra = (dayOfEra - dayOfEra / 1460 + dayOfEra / 36524 - dayOfEra / 146096) / 365;
    const uint32_t dayOfYear = dayOfEra - (365 * yearOfEra + yearOfEra / 4 - yearOfEra / 100);
    const uint32_t shiftedMonth = (5 * dayOfYear + 2) / 153;
    const uint32_t day = dayOfYear - (153 * shiftedMonth + 2) / 5 + 1;
    const uint32_t month = shiftedMonth < 10 ? shiftedMonth + 3 : shiftedMonth - 9;
    const int64_t year = static_cast<int64_t>(yearOfEra) + era * 400 + (month <= 2 ? 1 : 0);
    return Civil{year, month, day};
}

int64_t ruleDay(const TransitionRule& rule, int64_t year) {
    const int64_t january1 = daysFromCivil(year, 1, 1);
    switch (rule.kind) {
        case TransitionRule::Kind::JulianNoLeap:
            return january1 + rule.day - 1 + (isLeap(year) && rule.day >= kFirstJulianLeapShift ? 1 : 0);
        case TransitionRule::Kind::ZeroBasedDay:
            return january1 + rule.day;
        case TransitionRule::Kind::MonthWeekDay:
            break;
    }
    const int64_t first = daysFromCivil(year, rule.month, 1);
    const int64_t firstWeekday = floorMod(first + kThursday, kDaysPerWeek);
    int64_t day = (rule.day - firstWeekday + kDaysPerWeek) % kDaysPerWeek + kDaysPerWeek * (rule.week - 1);
    if (day >= daysInMonth(year, rule.month)) {
        day -= kDaysPerWeek;
    }
    return first + day;
}

struct Transition {
    int64_t at;
    int64_t year;
    uint8_t order;
    bool startsDaylight;
};

bool later(const Transition& a, const Transition& b) {
    if (a.at != b.at) {
        return a.at > b.at;
    }
    if (a.year != b.year) {
        return a.year > b.year;
    }
    return a.order > b.order;
}

}

bool parseTimeZone(std::string_view text, TimeZone& out) {
    if (text.empty() || text.size() > kMaxTimeZoneLength) {
        return false;
    }
    Cursor cursor(text);
    TimeZone zone;
    int32_t posixOffset = 0;
    if (!parseName(cursor) || !parseClock(cursor, 2, kMaxOffsetSeconds, true, posixOffset)) {
        return false;
    }
    zone.standardOffset = -posixOffset;
    if (cursor.done()) {
        out = zone;
        return true;
    }
    if (!parseName(cursor)) {
        return false;
    }
    zone.hasDaylight = true;
    zone.daylightOffset = zone.standardOffset + kSecondsPerHour;
    if (cursor.current() != ',') {
        if (!parseClock(cursor, 2, kMaxOffsetSeconds, true, posixOffset)) {
            return false;
        }
        zone.daylightOffset = -posixOffset;
    }
    const bool daylightFits = zone.daylightOffset > -kOffsetLimitSeconds && zone.daylightOffset < kOffsetLimitSeconds;
    const bool rules = daylightFits && cursor.accept(',') && parseRule(cursor, zone.start) && cursor.accept(',') &&
                       parseRule(cursor, zone.end) && cursor.done();
    if (!rules) {
        return false;
    }
    out = zone;
    return true;
}

int32_t utcOffsetAt(const TimeZone& zone, int64_t utcSeconds) {
    if (!zone.hasDaylight) {
        return zone.standardOffset;
    }
    const int64_t year = civilFromDays(floorDiv(utcSeconds + zone.standardOffset, kSecondsPerDay)).year;
    bool found = false;
    Transition latest{};
    for (int64_t candidateYear = year - 1; candidateYear <= year + 1; ++candidateYear) {
        const Transition candidates[] = {
            {ruleDay(zone.start, candidateYear) * kSecondsPerDay + zone.start.timeSeconds - zone.standardOffset,
             candidateYear, 0, true},
            {ruleDay(zone.end, candidateYear) * kSecondsPerDay + zone.end.timeSeconds - zone.daylightOffset,
             candidateYear, 1, false},
        };
        for (const Transition& candidate : candidates) {
            if (candidate.at <= utcSeconds && (!found || later(candidate, latest))) {
                latest = candidate;
                found = true;
            }
        }
    }
    return found && latest.startsDaylight ? zone.daylightOffset : zone.standardOffset;
}

std::string localTimestamp(int64_t utcSeconds, int32_t utcOffsetSeconds) {
    const int64_t local = utcSeconds + utcOffsetSeconds;
    const int64_t days = floorDiv(local, kSecondsPerDay);
    const int64_t secondsOfDay = local - days * kSecondsPerDay;
    const Civil date = civilFromDays(days);
    const int32_t magnitude = utcOffsetSeconds < 0 ? -utcOffsetSeconds : utcOffsetSeconds;
    char text[64];
    std::snprintf(text, sizeof(text), "%04lld-%02u-%02uT%02d:%02d:%02d%c%02d:%02d", static_cast<long long>(date.year),
                  static_cast<unsigned>(date.month), static_cast<unsigned>(date.day),
                  static_cast<int>(secondsOfDay / kSecondsPerHour),
                  static_cast<int>(secondsOfDay % kSecondsPerHour / kSecondsPerMinute),
                  static_cast<int>(secondsOfDay % kSecondsPerMinute), utcOffsetSeconds < 0 ? '-' : '+',
                  static_cast<int>(magnitude / kSecondsPerHour),
                  static_cast<int>(magnitude % kSecondsPerHour / kSecondsPerMinute));
    return text;
}

}
