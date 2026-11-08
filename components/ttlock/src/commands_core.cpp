// SPDX-License-Identifier: GPL-3.0-or-later
// Ported from kind3r/ttlock-sdk-js (GPL-3.0) src/api/Commands: AESKey, AddAdmin, CalibrationTime, CheckAdmin,
// CheckRandom, CheckUserTime, Unlock, Lock, SearchBicycleStatus, ReadDeviceInfo, SetAdminKeyboardPwd, GetAdminCode
// (its declared length, not its slice, which drops two bytes) and InitPasswords. The feature-word stitching and the
// sum wrap follow roquerodrigo/ttlock-ble (MIT).
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <string>
#include <utility>

#include "ttlock/commands.h"
#include "wire_format.h"

namespace ttlock {
namespace {

constexpr char kVendor[] = "SCIENER";
constexpr size_t kVendorSize = sizeof(kVendor) - 1;
constexpr size_t kAesKeySize = 16;
constexpr size_t kFeatureWordSize = 4;
constexpr size_t kFeatureWords = 2;
constexpr size_t kOperationRecordSize = 15;
constexpr size_t kAdminCodeHeaderSize = 2;
constexpr size_t kAdminCodeLengthIndex = 1;
constexpr int64_t kSecondsPerDay = 86400;
constexpr LockTime kUserTimeStart{2000, 1, 31, 14, 0, 0};
constexpr LockTime kUserTimeEnd{2099, 11, 30, 14, 0, 0};

Bytes vendorBytes() {
    return Bytes(kVendor, kVendor + kVendorSize);
}

void appendLockFlagPos(Bytes& out, uint32_t lockFlagPos) {
    wire::appendBe(out, lockFlagPos & 0xFFFFFF, 3);
}

int64_t floorDiv(int64_t value, int64_t divisor) {
    const int64_t quotient = value / divisor;
    return (value % divisor != 0 && value < 0) ? quotient - 1 : quotient;
}

void appendCodeSecret(Bytes& out, const CodeSecret& seed) {
    out.push_back(static_cast<uint8_t>(seed.code >> 4));
    out.push_back(static_cast<uint8_t>(((seed.code << 4) & 0xF0) | ((seed.secret >> 32) & 0xFF)));
    wire::appendBe(out, seed.secret & 0xFFFFFFFF, 4);
}

}

bool parseReply(const Bytes& plain, Reply& out) {
    if (plain.size() < 2) {
        return false;
    }
    out.command = plain[0];
    out.status = plain[1];
    out.data.assign(plain.begin() + 2, plain.end());
    return true;
}

LockTime lockTimeFromEpoch(int64_t seconds) {
    const int64_t days = floorDiv(seconds, kSecondsPerDay);
    const int64_t secondOfDay = seconds - days * kSecondsPerDay;
    const int64_t shifted = days + 719468;
    const int64_t era = floorDiv(shifted, 146097);
    const int64_t dayOfEra = shifted - era * 146097;
    const int64_t yearOfEra = (dayOfEra - dayOfEra / 1460 + dayOfEra / 36524 - dayOfEra / 146096) / 365;
    const int64_t dayOfYear = dayOfEra - (365 * yearOfEra + yearOfEra / 4 - yearOfEra / 100);
    const int64_t monthIndex = (5 * dayOfYear + 2) / 153;
    const int64_t month = monthIndex < 10 ? monthIndex + 3 : monthIndex - 9;
    const int64_t year = yearOfEra + era * 400 + (month <= 2 ? 1 : 0);
    LockTime time;
    time.year = static_cast<uint16_t>(year);
    time.month = static_cast<uint8_t>(month);
    time.day = static_cast<uint8_t>(dayOfYear - (153 * monthIndex + 2) / 5 + 1);
    time.hour = static_cast<uint8_t>(secondOfDay / 3600);
    time.minute = static_cast<uint8_t>(secondOfDay % 3600 / 60);
    time.second = static_cast<uint8_t>(secondOfDay % 60);
    return time;
}

Bytes buildGetAesKey() {
    return vendorBytes();
}

bool parseAesKey(const Bytes& data, AesKey& out) {
    if (data.size() != kAesKeySize) {
        return false;
    }
    std::copy(data.begin(), data.end(), out.begin());
    return true;
}

Bytes buildAddAdmin(uint32_t adminPs, uint32_t unlockKey) {
    Bytes out;
    wire::appendBe(out, adminPs, 4);
    wire::appendBe(out, unlockKey, 4);
    const Bytes vendor = vendorBytes();
    out.insert(out.end(), vendor.begin(), vendor.end());
    return out;
}

bool isAddAdminAccepted(const Bytes& data) {
    return data.size() == kVendorSize && std::memcmp(data.data(), kVendor, kVendorSize) == 0;
}

Bytes buildCalibrateTime(const LockTime& localTime) {
    Bytes out;
    wire::appendTime(out, localTime, true);
    return out;
}

Bytes buildCheckAdmin(uint32_t adminPs, uint32_t lockFlagPos, uint32_t uid) {
    Bytes out;
    wire::appendBe(out, adminPs, 4);
    appendLockFlagPos(out, lockFlagPos);
    wire::appendBe(out, uid, 4);
    return out;
}

Bytes buildCheckRandom(uint32_t psFromLock, uint32_t unlockKey) {
    Bytes out;
    wire::appendBe(out, static_cast<uint32_t>(psFromLock + unlockKey), 4);
    return out;
}

Bytes buildCheckUserTime(uint32_t lockFlagPos, uint32_t uid) {
    Bytes out;
    wire::appendTime(out, kUserTimeStart, false);
    wire::appendTime(out, kUserTimeEnd, false);
    appendLockFlagPos(out, lockFlagPos);
    wire::appendBe(out, uid, 4);
    return out;
}

bool parsePsFromLock(const Bytes& data, uint32_t& out) {
    if (data.size() < 4) {
        return false;
    }
    out = wire::readBe32(data.data());
    return true;
}

Bytes buildLockControl(uint32_t psFromLock, uint32_t unlockKey, uint32_t utcSeconds) {
    Bytes out;
    wire::appendBe(out, static_cast<uint32_t>(psFromLock + unlockKey), 4);
    wire::appendBe(out, utcSeconds, 4);
    return out;
}

OperationResult parseOperationResult(const Bytes& data) {
    OperationResult result;
    if (data.empty()) {
        return result;
    }
    result.battery = data[0];
    if (data.size() < kOperationRecordSize) {
        return result;
    }
    result.hasRecord = true;
    result.uid = wire::readBe32(data.data() + 1);
    result.recordId = wire::readBe32(data.data() + 5);
    result.time = wire::readTime(data.data() + 9, true);
    return result;
}

Bytes buildSearchStatus() {
    return vendorBytes();
}

bool parseLockStatus(const Bytes& data, LockStatus& out) {
    if (data.size() < 2) {
        return false;
    }
    out.battery = data[0];
    switch (data[1]) {
        case static_cast<uint8_t>(LockState::Locked):
            out.state = LockState::Locked;
            break;
        case static_cast<uint8_t>(LockState::Unlocked):
            out.state = LockState::Unlocked;
            break;
        default:
            out.state = LockState::Unknown;
            break;
    }
    return true;
}

bool parseFeatures(const Bytes& data, uint64_t& out) {
    if (data.size() < 1 + kFeatureWordSize) {
        return false;
    }
    const size_t words = std::min((data.size() - 1) / kFeatureWordSize, kFeatureWords);
    uint64_t mask = 0;
    for (size_t i = 0; i < words; ++i) {
        mask |= static_cast<uint64_t>(wire::readBe32(data.data() + 1 + i * kFeatureWordSize)) << (32 * i);
    }
    out = mask;
    return true;
}

Bytes buildReadDeviceInfo(DeviceInfoItem item) {
    return Bytes{static_cast<uint8_t>(item)};
}

std::string parseDeviceInfoString(const Bytes& data) {
    const auto end = std::find(data.begin(), data.end(), uint8_t{0});
    return std::string(data.begin(), end);
}

Bytes buildSetAdminPasscode(const std::string& digits) {
    Bytes out;
    out.reserve(digits.size());
    for (char digit : digits) {
        out.push_back(static_cast<uint8_t>(digit - '0'));
    }
    return out;
}

bool parseAdminCode(const Bytes& data, std::string& out) {
    if (data.size() < kAdminCodeHeaderSize) {
        return false;
    }
    const size_t length = data[kAdminCodeLengthIndex];
    if (data.size() < kAdminCodeHeaderSize + length) {
        return false;
    }
    const auto begin = data.begin() + kAdminCodeHeaderSize;
    std::string code(begin, begin + static_cast<std::ptrdiff_t>(length));
    for (char digit : code) {
        if (digit < '0' || digit > '9') {
            return false;
        }
    }
    out = std::move(code);
    return true;
}

Bytes buildInitPasswords(uint8_t yearOfCentury, const std::array<CodeSecret, kCodeSecretCount>& seeds) {
    Bytes out{yearOfCentury};
    for (const CodeSecret& seed : seeds) {
        appendCodeSecret(out, seed);
    }
    return out;
}

}
