// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "ttlock/bytes.h"
#include "ttlock/frame.h"

namespace ttlock {

struct LockKeys {
    std::string mac;
    LockVersion version;
    AesKey aesKey{};
    uint32_t adminPs = 0;
    uint32_t unlockKey = 0;
    uint32_t lockFlagPos = 0;
    uint64_t features = 0;
    std::string adminPasscode;
};

inline constexpr size_t kCodeSecretCount = 10;

struct CodeSecret {
    uint16_t code = 0;
    uint64_t secret = 0;
};

struct DeviceInfo {
    std::string model;
    std::string hardware;
    std::string firmware;
    std::string manufactureDate;
    std::string name;
};

struct LockTime {
    uint16_t year = 2000;
    uint8_t month = 1;
    uint8_t day = 1;
    uint8_t hour = 0;
    uint8_t minute = 0;
    uint8_t second = 0;

    bool operator==(const LockTime&) const = default;
};

inline constexpr LockTime kPermanentStart{2000, 1, 1, 0, 0, 0};
inline constexpr LockTime kPermanentEnd{2099, 1, 1, 0, 0, 0};

struct Validity {
    LockTime start = kPermanentStart;
    LockTime end = kPermanentEnd;

    bool operator==(const Validity&) const = default;
};

enum class LockState : uint8_t {
    Locked = 0,
    Unlocked = 1,
    Unknown = 0xFF,
};

struct LockStatus {
    LockState state = LockState::Unknown;
    int battery = -1;
};

struct OperationResult {
    int battery = -1;
    bool hasRecord = false;
    uint32_t uid = 0;
    uint32_t recordId = 0;
    LockTime time;
};

struct AutoLockSetting {
    uint16_t seconds = 0;
    uint16_t minSeconds = 0;
    uint16_t maxSeconds = 0;
};

struct SoundSetting {
    bool enabled = false;
    uint8_t volume = 0;
};

enum class PassageType : uint8_t {
    Weekly = 1,
    Monthly = 2,
};

struct PassageMode {
    PassageType type = PassageType::Weekly;
    uint8_t weekOrDay = 0;
    uint8_t month = 0;
    uint8_t startHour = 0;
    uint8_t startMinute = 0;
    uint8_t endHour = 0;
    uint8_t endMinute = 0;

    bool operator==(const PassageMode&) const = default;
};

enum class PasscodeType : uint8_t {
    Permanent = 1,
    Count = 2,
    Period = 3,
    Cyclic = 4,
};

struct Passcode {
    PasscodeType type = PasscodeType::Permanent;
    std::string code;
    Validity validity;
};

inline constexpr size_t kMinPasscodeDigits = 4;
inline constexpr size_t kMaxPasscodeDigits = 9;

inline bool isPasscode(std::string_view code) {
    if (code.size() < kMinPasscodeDigits || code.size() > kMaxPasscodeDigits) {
        return false;
    }
    for (char digit : code) {
        if (digit < '0' || digit > '9') {
            return false;
        }
    }
    return true;
}

struct Credential {
    uint64_t id = 0;
    Validity validity;
};

struct WeeklyCycle {
    uint8_t weekDay = 1;
    uint16_t startMinuteOfDay = 0;
    uint16_t endMinuteOfDay = 0;
};

struct LogEntry {
    uint16_t recordNumber = 0;
    uint8_t type = 0;
    LockTime time;
    uint8_t battery = 0;
    uint32_t uid = 0;
    uint32_t recordId = 0;
    std::string credential;
    std::string newCredential;
    int keyId = -1;
    int accessoryBattery = -1;
};

struct LockEvent {
    uint8_t command = 0;
    uint8_t status = 0;
    Bytes data;
    int battery = -1;
    LockState state = LockState::Unknown;
    bool hasRecord = false;
    uint32_t uid = 0;
    uint32_t recordId = 0;
    LockTime time;
};

enum class EnrollStage : uint8_t {
    Waiting,
    Scanned,
};

struct EnrollProgress {
    EnrollStage stage = EnrollStage::Waiting;
    uint8_t scans = 0;
};

}
