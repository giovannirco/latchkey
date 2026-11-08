// SPDX-License-Identifier: GPL-3.0-or-later
// The unlock record types follow kind3r/ttlock-sdk-js (GPL-3.0) src/constant/LogOperate.ts and the UNLOCK list of
// src/constant/LogOperateCategory.ts, with the app, gateway, admin-code and double-check unlock types of
// roquerodrigo/ttlock-ble (MIT) constants/log_operate.py.
#include "latchkey_util/unlock_alert.h"

#include <cstddef>
#include <initializer_list>

namespace latchkey_util {

namespace {

constexpr int64_t kSecondsPerDay = 86400;

struct TypeMethod {
    uint8_t type;
    UnlockMethod method;
};

constexpr TypeMethod kUnlockTypes[] = {
    {1, UnlockMethod::App},
    {75, UnlockMethod::App},
    {77, UnlockMethod::App},
    {3, UnlockMethod::Remote},
    {28, UnlockMethod::Remote},
    {76, UnlockMethod::Remote},
    {4, UnlockMethod::Passcode},
    {78, UnlockMethod::Passcode},
    {92, UnlockMethod::Passcode},
    {20, UnlockMethod::Fingerprint},
    {79, UnlockMethod::Fingerprint},
    {17, UnlockMethod::Card},
    {80, UnlockMethod::Card},
    {27, UnlockMethod::MechanicalKey},
    {19, UnlockMethod::Wristband},
    {29, UnlockMethod::Forced},
    {50, UnlockMethod::Other},
    {57, UnlockMethod::Other},
    {67, UnlockMethod::Other},
    {81, UnlockMethod::Other},
    {82, UnlockMethod::Other},
    {83, UnlockMethod::Other},
    {84, UnlockMethod::Other},
    {94, UnlockMethod::Other},
    {111, UnlockMethod::Other},
};

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

bool lockSeconds(const ttlock::LockTime& time, int64_t& out) {
    if (time.month < 1 || time.month > 12 || time.day < 1 || time.day > daysInMonth(time.year, time.month) ||
        time.hour > 23 || time.minute > 59 || time.second > 59) {
        return false;
    }
    out = daysFromCivil(time.year, time.month, time.day) * kSecondsPerDay + time.hour * 3600 + time.minute * 60 +
          time.second;
    return true;
}

bool needsExplaining(UnlockMethod method) { return method == UnlockMethod::App || method == UnlockMethod::Remote; }

class Matcher {
public:
    Matcher(const std::vector<LatchkeyUnlock>& performed, uint32_t toleranceSeconds)
        : performed_(performed), used_(performed.size(), false), tolerance_(toleranceSeconds) {}

    bool claim(const ttlock::LogEntry& entry, UnlockMethod method, int64_t utc, bool byRecord) {
        for (size_t i = 0; i < performed_.size(); ++i) {
            const LatchkeyUnlock& unlock = performed_[i];
            if (used_[i] || unlock.method != method || unlock.recordId.has_value() != byRecord) {
                continue;
            }
            if (byRecord && *unlock.recordId != entry.recordId) {
                continue;
            }
            if (utc < unlock.fromUtc - tolerance_ || utc > unlock.toUtc + tolerance_) {
                continue;
            }
            used_[i] = true;
            return true;
        }
        return false;
    }

private:
    const std::vector<LatchkeyUnlock>& performed_;
    std::vector<bool> used_;
    int64_t tolerance_;
};

}

UnlockMethod unlockMethodOf(uint8_t recordType) {
    for (const TypeMethod& known : kUnlockTypes) {
        if (known.type == recordType) {
            return known.method;
        }
    }
    return UnlockMethod::None;
}

const char* toString(UnlockMethod method) {
    switch (method) {
        case UnlockMethod::None:
            return "none";
        case UnlockMethod::App:
            return "app";
        case UnlockMethod::Remote:
            return "remote";
        case UnlockMethod::Passcode:
            return "passcode";
        case UnlockMethod::Fingerprint:
            return "fingerprint";
        case UnlockMethod::Card:
            return "card";
        case UnlockMethod::MechanicalKey:
            return "key";
        case UnlockMethod::Wristband:
            return "wristband";
        case UnlockMethod::Forced:
            return "forced";
        case UnlockMethod::Other:
            return "other";
    }
    return "none";
}

std::vector<UnlockFinding> classifyUnlocks(const std::vector<ttlock::LogEntry>& entries,
                                           const std::vector<LatchkeyUnlock>& performed, int32_t lockUtcOffsetSeconds,
                                           uint32_t toleranceSeconds) {
    std::vector<UnlockFinding> findings(entries.size());
    std::vector<int64_t> utc(entries.size(), 0);
    std::vector<bool> datable(entries.size(), false);
    for (size_t i = 0; i < entries.size(); ++i) {
        const UnlockMethod method = unlockMethodOf(entries[i].type);
        findings[i].method = method;
        if (method == UnlockMethod::None) {
            continue;
        }
        if (!needsExplaining(method)) {
            findings[i].verdict = UnlockVerdict::Reported;
            continue;
        }
        findings[i].verdict = UnlockVerdict::Alert;
        int64_t local = 0;
        datable[i] = lockSeconds(entries[i].time, local);
        utc[i] = local - lockUtcOffsetSeconds;
    }
    Matcher matcher(performed, toleranceSeconds);
    for (const bool byRecord : {true, false}) {
        for (size_t i = 0; i < entries.size(); ++i) {
            if (findings[i].verdict == UnlockVerdict::Alert && datable[i] &&
                matcher.claim(entries[i], findings[i].method, utc[i], byRecord)) {
                findings[i].verdict = UnlockVerdict::Latchkey;
            }
        }
    }
    return findings;
}

}
