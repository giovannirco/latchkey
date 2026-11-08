// SPDX-License-Identifier: GPL-3.0-or-later
// Ported from kind3r/ttlock-sdk-js (GPL-3.0) src/device/TTLock.ts and src/device/TTLockApi.ts: the pairing
// sequence of initLock.
#include "ttlock/session.h"

#include <array>
#include <functional>
#include <string>
#include <utility>

#include "session_internal.h"
#include "ttlock/aes.h"
#include "ttlock/commands.h"

namespace ttlock {
namespace {

constexpr uint32_t kSecretBound = 999999999;
constexpr uint32_t kCodeBound = 1071;
constexpr uint32_t kDigitBound = 10;
constexpr size_t kSecretDigits = 10;

struct OptionalRead {
    uint64_t features;
    uint8_t command;
    Bytes (*payload)();
};

const OptionalRead kPairingReads[] = {
    {featureBit(Feature::ResetButton) | featureBit(Feature::TamperAlert) | featureBit(Feature::PrivacyLock),
     command::kSwitch, buildSwitchQuery},
    {featureBit(Feature::AudioManagement), command::kAudioManage, buildSoundQuery},
    {featureBit(Feature::PasswordDisplayOrHide), command::kShowPassword, buildScreenPasscodeQuery},
    {featureBit(Feature::AutoLock), command::kAutoLockManage, buildAutoLockQuery},
    {featureBit(Feature::GetAdminCode), command::kGetAdminCode, noPayload},
};

}

uint32_t Session::uniformBelow(uint32_t bound) {
    const uint64_t range = uint64_t{1} << 32;
    const uint64_t limit = range - range % bound;
    while (true) {
        uint8_t bytes[4];
        random_.fill(bytes, sizeof(bytes));
        const uint64_t value = uint64_t{bytes[0]} << 24 | uint64_t{bytes[1]} << 16 | uint64_t{bytes[2]} << 8 | bytes[3];
        if (value < limit) {
            return static_cast<uint32_t>(value % bound);
        }
    }
}

uint32_t Session::randomSecret() {
    return 1 + uniformBelow(kSecretBound);
}

std::string Session::randomDigits(size_t count) {
    std::string digits;
    digits.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        digits.push_back(static_cast<char>('0' + uniformBelow(kDigitBound)));
    }
    return digits;
}

Status Session::pair(const LockVersion& version, LockKeys& out, PersistCallback persistEarly, PairResult& result) {
    result = PairResult{};
    if (!usesV3Frames(version)) {
        return Status::Unsupported;
    }
    if (!timeUsable()) {
        return Status::TimeUnsynced;
    }
    attached_ = false;
    LockKeys fresh;
    fresh.mac = out.mac;
    fresh.version = version;
    fresh.aesKey = kDefaultAesKey;
    keys_ = std::move(fresh);
    Status status = initialize();
    if (status != Status::Ok) {
        return status;
    }
    status = fetchAesKey();
    if (status != Status::Ok) {
        return status;
    }
    keys_.adminPs = randomSecret();
    keys_.unlockKey = randomSecret();
    status = addAdmin();
    if (status == Status::LockError) {
        return status;
    }
    attached_ = true;
    const std::function<void()> persist = [this, &out, &persistEarly]() {
        out = keys_;
        if (persistEarly) {
            persistEarly(keys_);
        }
    };
    persist();
    if (status != Status::Ok) {
        return Status::PairIncomplete;
    }
    status = finishPairing(persist, result);
    out = keys_;
    if (status != Status::Ok) {
        return Status::PairIncomplete;
    }
    persist();
    return Status::Ok;
}

Status Session::initialize() {
    const Status sent = sendCommand(command::kInitialization, noPayload());
    if (sent != Status::Ok) {
        return sent;
    }
    size_t budget = kMaxFramesPerReply;
    DecodedFrame frame;
    const Status received = nextFrame(kCommandTimeoutMs, budget, frame);
    if (received != Status::Ok) {
        return received;
    }
    return frame.crcOk ? Status::Ok : Status::BadCrc;
}

Status Session::fetchAesKey() {
    Bytes data;
    const Status status = request(command::kGetAesKey, buildGetAesKey(), data);
    if (status != Status::Ok) {
        return status;
    }
    AesKey key{};
    if (!parseAesKey(data, key)) {
        return Status::BadResponse;
    }
    keys_.aesKey = key;
    return Status::Ok;
}

Status Session::addAdmin() {
    Bytes data;
    const Status status = request(command::kAddAdmin, buildAddAdmin(keys_.adminPs, keys_.unlockKey), data);
    if (status != Status::Ok) {
        return status;
    }
    return isAddAdminAccepted(data) ? Status::Ok : Status::BadResponse;
}

Status Session::finishPairing(const std::function<void()>& persist, PairResult& result) {
    Bytes data;
    Status status = request(command::kTimeCalibrate, buildCalibrateTime(localNow()), data);
    if (status == Status::Ok) {
        result.timeCalibrated = true;
    } else if (status != Status::LockError && status != Status::Timeout) {
        return status;
    }
    status = request(command::kSearchDeviceFeature, noPayload(), data);
    if (status != Status::Ok) {
        return status;
    }
    if (!parseFeatures(data, keys_.features)) {
        return Status::BadResponse;
    }
    for (const OptionalRead& read : kPairingReads) {
        if ((keys_.features & read.features) == 0) {
            continue;
        }
        status = optionalRead(read.command, read.payload());
        if (status != Status::Ok) {
            return status;
        }
    }
    const std::string previous = keys_.adminPasscode;
    keys_.adminPasscode = randomDigits(kAdminPasscodeDigits);
    persist();
    status = request(command::kSetAdminKeyboardPassword, buildSetAdminPasscode(keys_.adminPasscode), data);
    if (status == Status::LockError) {
        keys_.adminPasscode = previous;
        persist();
        return status;
    }
    if (status == Status::Ok) {
        result.adminPasscodeConfirmed = true;
    } else if (status != Status::Timeout) {
        return status;
    }
    status = initPasswords();
    if (status != Status::Ok) {
        return status;
    }
    if (hasFeature(keys_.features, Feature::ConfigGatewayUnlock)) {
        status = optionalRead(command::kControlRemoteUnlock, buildRemoteUnlockQuery());
        if (status != Status::Ok) {
            return status;
        }
    }
    return request(command::kOperateFinished, noPayload(), data);
}

Status Session::initPasswords() {
    const LockTime now = localNow();
    const bool newYearsDay = now.month == 1 && now.day == 1;
    const uint16_t year = newYearsDay ? static_cast<uint16_t>(now.year - 1) : now.year;
    std::array<CodeSecret, kCodeSecretCount> seeds{};
    for (CodeSecret& seed : seeds) {
        seed.code = static_cast<uint16_t>(uniformBelow(kCodeBound));
        for (size_t i = 0; i < kSecretDigits; ++i) {
            seed.secret = seed.secret * kDigitBound + uniformBelow(kDigitBound);
        }
    }
    Bytes data;
    return request(command::kInitPasswords, buildInitPasswords(static_cast<uint8_t>(year % 100), seeds), data);
}

}
