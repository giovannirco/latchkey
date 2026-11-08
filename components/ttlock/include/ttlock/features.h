// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace ttlock {

enum class Feature : uint8_t {
    Passcode = 0,
    Ic = 1,
    FingerPrint = 2,
    WristBand = 3,
    AutoLock = 4,
    PasscodeWithDeleteFunction = 5,
    FirmwareSetting = 6,
    ModifyPasscodeFunction = 7,
    ManualLock = 8,
    PasswordDisplayOrHide = 9,
    GatewayUnlock = 10,
    FreezeLock = 11,
    CyclicPassword = 12,
    Magnetometer = 13,
    ConfigGatewayUnlock = 14,
    AudioManagement = 15,
    NbLock = 16,
    GetAdminCode = 18,
    HotelLock = 19,
    LockNoClockChip = 20,
    CanNotClickUnlock = 21,
    PassageMode = 22,
    PassageModeAndAutoLockAndCanClose = 23,
    WirelessKeyboard = 24,
    Lamp = 25,
    TamperAlert = 28,
    ResetButton = 29,
    PrivacyLock = 30,
    DeadLock = 32,
    CyclicIcOrFingerPrint = 34,
    UnlockDirection = 36,
    FingerVein = 37,
    TelinkChip = 38,
    NbActivateConfiguration = 39,
    CyclicPasscodeCanRecovery = 40,
    WirelessKeyFob = 41,
    AccessoryBattery = 42,
};

inline constexpr Feature kAllFeatures[] = {
    Feature::Passcode,
    Feature::Ic,
    Feature::FingerPrint,
    Feature::WristBand,
    Feature::AutoLock,
    Feature::PasscodeWithDeleteFunction,
    Feature::FirmwareSetting,
    Feature::ModifyPasscodeFunction,
    Feature::ManualLock,
    Feature::PasswordDisplayOrHide,
    Feature::GatewayUnlock,
    Feature::FreezeLock,
    Feature::CyclicPassword,
    Feature::Magnetometer,
    Feature::ConfigGatewayUnlock,
    Feature::AudioManagement,
    Feature::NbLock,
    Feature::GetAdminCode,
    Feature::HotelLock,
    Feature::LockNoClockChip,
    Feature::CanNotClickUnlock,
    Feature::PassageMode,
    Feature::PassageModeAndAutoLockAndCanClose,
    Feature::WirelessKeyboard,
    Feature::Lamp,
    Feature::TamperAlert,
    Feature::ResetButton,
    Feature::PrivacyLock,
    Feature::DeadLock,
    Feature::CyclicIcOrFingerPrint,
    Feature::UnlockDirection,
    Feature::FingerVein,
    Feature::TelinkChip,
    Feature::NbActivateConfiguration,
    Feature::CyclicPasscodeCanRecovery,
    Feature::WirelessKeyFob,
    Feature::AccessoryBattery,
};

bool hasFeature(uint64_t features, Feature feature);
uint64_t featureBit(Feature feature);
const char* toString(Feature feature);

}
