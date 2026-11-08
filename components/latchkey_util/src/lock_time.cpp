// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/lock_time.h"

#include "ttlock/commands.h"

namespace latchkey_util {

namespace {

constexpr int64_t kSecondsPerDay = 86400;
constexpr uint16_t kFirstLockYear = 2000;
constexpr uint16_t kLastLockYear = 2099;

bool isLeap(int64_t year) { return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0; }

uint8_t daysInMonth(int64_t year, uint8_t month) {
    constexpr uint8_t kDays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    return month == 2 && isLeap(year) ? 29 : kDays[month - 1];
}

int64_t daysFromCivil(int64_t year, uint8_t month, uint8_t day) {
    year -= month <= 2 ? 1 : 0;
    const int64_t era = (year >= 0 ? year : year - 399) / 400;
    const int64_t yearOfEra = year - era * 400;
    const int64_t dayOfYear = (153 * (month > 2 ? month - 3 : month + 9) + 2) / 5 + day - 1;
    const int64_t dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear;
    return era * 146097 + dayOfEra - 719468;
}

bool inLockCalendar(const ttlock::LockTime& time) {
    return time.year >= kFirstLockYear && time.year <= kLastLockYear;
}

}

bool localSecondsOf(const ttlock::LockTime& time, int64_t& out) {
    if (time.month < 1 || time.month > 12 || time.day < 1 || time.day > daysInMonth(time.year, time.month) ||
        time.hour > 23 || time.minute > 59 || time.second > 59) {
        return false;
    }
    out = daysFromCivil(time.year, time.month, time.day) * kSecondsPerDay + time.hour * 3600 + time.minute * 60 +
          time.second;
    return true;
}

ttlock::LockTime lockTimeAt(int64_t utcSeconds, const UtcOffsetAt& offsetAt) {
    return ttlock::lockTimeFromEpoch(utcSeconds + offsetAt(utcSeconds));
}

bool utcOfLockTime(const ttlock::LockTime& time, const UtcOffsetAt& offsetAt, int64_t& out) {
    int64_t local = 0;
    if (!localSecondsOf(time, local)) {
        return false;
    }
    const int64_t guess = local - offsetAt(local);
    out = local - offsetAt(guess);
    return true;
}

bool lockValidity(int64_t startUtc, int64_t endUtc, const UtcOffsetAt& offsetAt, ttlock::Validity& out) {
    if (startUtc >= endUtc) {
        return false;
    }
    const ttlock::Validity validity{lockTimeAt(startUtc, offsetAt), lockTimeAt(endUtc, offsetAt)};
    if (!inLockCalendar(validity.start) || !inLockCalendar(validity.end)) {
        return false;
    }
    out = validity;
    return true;
}

bool isPermanent(const ttlock::Validity& validity) { return validity.end == ttlock::kPermanentEnd; }

}
