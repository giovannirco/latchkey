// SPDX-License-Identifier: GPL-3.0-or-later
// Feature bits from kind3r/ttlock-sdk-js (GPL-3.0) src/constant/FeatureValue.ts.
#include "ttlock/features.h"

namespace ttlock {

uint64_t featureBit(Feature feature) {
    return uint64_t{1} << static_cast<uint8_t>(feature);
}

bool hasFeature(uint64_t features, Feature feature) {
    return (features & featureBit(feature)) != 0;
}

const char* toString(Feature feature) {
    switch (feature) {
        case Feature::Passcode:
            return "passcode";
        case Feature::Ic:
            return "ic";
        case Feature::FingerPrint:
            return "finger_print";
        case Feature::WristBand:
            return "wrist_band";
        case Feature::AutoLock:
            return "auto_lock";
        case Feature::PasscodeWithDeleteFunction:
            return "passcode_with_delete_function";
        case Feature::FirmwareSetting:
            return "firmware_setting";
        case Feature::ModifyPasscodeFunction:
            return "modify_passcode_function";
        case Feature::ManualLock:
            return "manual_lock";
        case Feature::PasswordDisplayOrHide:
            return "password_display_or_hide";
        case Feature::GatewayUnlock:
            return "gateway_unlock";
        case Feature::FreezeLock:
            return "freeze_lock";
        case Feature::CyclicPassword:
            return "cyclic_password";
        case Feature::Magnetometer:
            return "magnetometer";
        case Feature::ConfigGatewayUnlock:
            return "config_gateway_unlock";
        case Feature::AudioManagement:
            return "audio_management";
        case Feature::NbLock:
            return "nb_lock";
        case Feature::GetAdminCode:
            return "get_admin_code";
        case Feature::HotelLock:
            return "hotel_lock";
        case Feature::LockNoClockChip:
            return "lock_no_clock_chip";
        case Feature::CanNotClickUnlock:
            return "can_not_click_unlock";
        case Feature::PassageMode:
            return "passage_mode";
        case Feature::PassageModeAndAutoLockAndCanClose:
            return "passage_mode_and_auto_lock_and_can_close";
        case Feature::WirelessKeyboard:
            return "wireless_keyboard";
        case Feature::Lamp:
            return "lamp";
        case Feature::TamperAlert:
            return "tamper_alert";
        case Feature::ResetButton:
            return "reset_button";
        case Feature::PrivacyLock:
            return "privacy_lock";
        case Feature::DeadLock:
            return "dead_lock";
        case Feature::CyclicIcOrFingerPrint:
            return "cyclic_ic_or_finger_print";
        case Feature::UnlockDirection:
            return "unlock_direction";
        case Feature::FingerVein:
            return "finger_vein";
        case Feature::TelinkChip:
            return "telink_chip";
        case Feature::NbActivateConfiguration:
            return "nb_activate_configuration";
        case Feature::CyclicPasscodeCanRecovery:
            return "cyclic_passcode_can_recovery";
        case Feature::WirelessKeyFob:
            return "wireless_key_fob";
        case Feature::AccessoryBattery:
            return "accessory_battery";
    }
    return "unknown";
}

}
