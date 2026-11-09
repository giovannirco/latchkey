// SPDX-License-Identifier: GPL-3.0-or-later
// Ported from kind3r/ttlock-sdk-js (GPL-3.0) src/device/TTLock.ts and src/device/TTLockApi.ts: the time
// calibration, auto-lock, passage mode, sound, remote unlock and screen passcode flows.
#include "ttlock/session.h"

#include <vector>

#include "session_internal.h"
#include "ttlock/commands.h"

namespace ttlock {
namespace {

constexpr uint8_t kMinVolume = 1;
constexpr uint8_t kMaxVolume = 5;
constexpr uint8_t kLastWeekday = 7;
constexpr uint8_t kLastMonthDay = 31;
constexpr uint32_t kPassageAddTimeoutMs = 10000;

bool isValidPassage(const PassageMode& mode) {
    const bool weekly = mode.type == PassageType::Weekly && mode.weekOrDay <= kLastWeekday;
    const bool monthly = mode.type == PassageType::Monthly && mode.weekOrDay >= 1 && mode.weekOrDay <= kLastMonthDay;
    return (weekly || monthly) && mode.startHour <= 23 && mode.endHour <= 23 && mode.startMinute <= 59 &&
           mode.endMinute <= 59;
}

}

Status Session::syncTime() {
    Status status = requireKeys();
    if (status != Status::Ok) {
        return status;
    }
    if (!timeUsable()) {
        return Status::TimeUnsynced;
    }
    status = adminLogin();
    if (status != Status::Ok) {
        return status;
    }
    Bytes data;
    return request(command::kTimeCalibrate, buildCalibrateTime(localNow()), data);
}

Status Session::autolockGet(AutoLockSetting& out) {
    Bytes data;
    const Status status = adminRequest(Feature::AutoLock, command::kAutoLockManage, buildAutoLockQuery(), data);
    if (status != Status::Ok) {
        return status;
    }
    return parseAutoLock(data, out) ? Status::Ok : Status::BadResponse;
}

Status Session::autolockSet(uint16_t seconds) {
    Bytes data;
    return adminRequest(Feature::AutoLock, command::kAutoLockManage, buildAutoLockSet(seconds), data);
}

Status Session::passageList(std::vector<PassageMode>& out) {
    const Status status = beginAdmin(Feature::PassageMode);
    if (status != Status::Ok) {
        return status;
    }
    return collectPages<PassagePage>(
        [this](uint16_t sequence, PassagePage& page) {
            Bytes data;
            const Status fetched =
                request(command::kConfigurePassageMode, buildPassageQuery(static_cast<uint8_t>(sequence)), data);
            if (fetched != Status::Ok) {
                return fetched;
            }
            return parsePassagePage(data, page) ? Status::Ok : Status::BadResponse;
        },
        out);
}

Status Session::passageAdd(const PassageMode& mode) {
    const Status status = requireFeature(Feature::PassageMode);
    if (status != Status::Ok) {
        return status;
    }
    if (!isValidPassage(mode)) {
        return Status::InvalidArgument;
    }
    const Status authenticated = beginAdmin(Feature::PassageMode);
    if (authenticated != Status::Ok) {
        return authenticated;
    }
    Bytes data;
    return request(command::kConfigurePassageMode, buildPassageAdd(mode), data, kPassageAddTimeoutMs);
}

Status Session::passageDelete(const PassageMode& mode) {
    const Status status = requireFeature(Feature::PassageMode);
    if (status != Status::Ok) {
        return status;
    }
    if (!isValidPassage(mode)) {
        return Status::InvalidArgument;
    }
    Bytes data;
    return adminRequest(Feature::PassageMode, command::kConfigurePassageMode, buildPassageDelete(mode), data);
}

Status Session::passageClear() {
    Bytes data;
    return adminRequest(Feature::PassageMode, command::kConfigurePassageMode, buildPassageClear(), data);
}

Status Session::soundGet(SoundSetting& out) {
    Bytes data;
    const Status status = adminRequest(Feature::AudioManagement, command::kAudioManage, buildSoundQuery(), data);
    if (status != Status::Ok) {
        return status;
    }
    return parseSound(data, out) ? Status::Ok : Status::BadResponse;
}

Status Session::soundSet(bool enabled) {
    Bytes data;
    return adminRequest(Feature::AudioManagement, command::kAudioManage, buildSoundSet(enabled), data);
}

Status Session::soundVolumeSet(uint8_t level) {
    const Status status = requireFeature(Feature::AudioManagement);
    if (status != Status::Ok) {
        return status;
    }
    if (level < kMinVolume || level > kMaxVolume) {
        return Status::InvalidArgument;
    }
    Bytes data;
    return adminRequest(Feature::AudioManagement, command::kAudioManage, buildSoundVolumeSet(level), data);
}

Status Session::switchGet(Feature feature, uint32_t item, bool& enabled) {
    Bytes data;
    const Status status = adminRequest(feature, command::kSwitch, buildSwitchQuery(), data);
    if (status != Status::Ok) {
        return status;
    }
    uint32_t value = 0;
    if (!parseSwitchState(data, value)) {
        return Status::BadResponse;
    }
    enabled = (value & item) != 0;
    return Status::Ok;
}

Status Session::switchSet(Feature feature, uint32_t item, bool enabled) {
    Bytes data;
    return adminRequest(feature, command::kSwitch, buildSwitchSet(item, enabled), data);
}

Status Session::resetButtonGet(bool& enabled) {
    return switchGet(Feature::ResetButton, kSwitchResetButton, enabled);
}

Status Session::resetButtonSet(bool enabled) {
    return switchSet(Feature::ResetButton, kSwitchResetButton, enabled);
}

Status Session::privacyLockGet(bool& enabled) {
    return switchGet(Feature::PrivacyLock, kSwitchPrivacyLock, enabled);
}

Status Session::privacyLockSet(bool enabled) {
    return switchSet(Feature::PrivacyLock, kSwitchPrivacyLock, enabled);
}

Status Session::tamperAlertGet(bool& enabled) {
    return switchGet(Feature::TamperAlert, kSwitchTamperAlert, enabled);
}

Status Session::tamperAlertSet(bool enabled) {
    return switchSet(Feature::TamperAlert, kSwitchTamperAlert, enabled);
}

Status Session::remoteUnlockGet(bool& enabled) {
    Bytes data;
    const Status status =
        adminRequest(Feature::ConfigGatewayUnlock, command::kControlRemoteUnlock, buildRemoteUnlockQuery(), data);
    if (status != Status::Ok) {
        return status;
    }
    return parseRemoteUnlock(data, enabled) ? Status::Ok : Status::BadResponse;
}

Status Session::remoteUnlockSet(bool enabled) {
    Bytes data;
    return adminRequest(Feature::ConfigGatewayUnlock, command::kControlRemoteUnlock, buildRemoteUnlockSet(enabled),
                        data);
}

Status Session::screenPasscodeGet(bool& visible) {
    Bytes data;
    const Status status =
        adminRequest(Feature::PasswordDisplayOrHide, command::kShowPassword, buildScreenPasscodeQuery(), data);
    if (status != Status::Ok) {
        return status;
    }
    return parseScreenPasscode(data, visible) ? Status::Ok : Status::BadResponse;
}

Status Session::screenPasscodeSet(bool visible) {
    Bytes data;
    return adminRequest(Feature::PasswordDisplayOrHide, command::kShowPassword, buildScreenPasscodeSet(visible), data);
}

}
