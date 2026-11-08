// SPDX-License-Identifier: GPL-3.0-or-later
// Codes 0x01-0x0A from kind3r/ttlock-sdk-js (GPL-3.0) src/constant/CommandResponse.ts; 0x0D and 0x1A as documented
// from hardware by roquerodrigo/ttlock-ble (MIT).
#include "ttlock/errors.h"

namespace ttlock {

const char* lockErrorName(uint8_t code) {
    switch (static_cast<LockErrorCode>(code)) {
        case LockErrorCode::InvalidCrc:
            return "invalid_crc";
        case LockErrorCode::NoPermission:
            return "no_permission";
        case LockErrorCode::WrongIdOrPassword:
            return "wrong_id_or_password";
        case LockErrorCode::ReachLimit:
            return "reach_limit";
        case LockErrorCode::InSetting:
            return "in_setting";
        case LockErrorCode::SameUserId:
            return "same_user_id";
        case LockErrorCode::NoAdminYet:
            return "no_admin_yet";
        case LockErrorCode::DynamicPasswordExpired:
            return "dynamic_password_expired";
        case LockErrorCode::NoData:
            return "no_data";
        case LockErrorCode::NoPower:
            return "no_power";
        case LockErrorCode::KeyFlagInvalid:
            return "key_flag_invalid";
        case LockErrorCode::CredentialNotFound:
            return "credential_not_found";
    }
    return "unknown";
}

}
