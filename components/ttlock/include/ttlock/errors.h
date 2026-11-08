// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace ttlock {

enum class LockErrorCode : uint8_t {
    InvalidCrc = 0x01,
    NoPermission = 0x02,
    WrongIdOrPassword = 0x03,
    ReachLimit = 0x04,
    InSetting = 0x05,
    SameUserId = 0x06,
    NoAdminYet = 0x07,
    DynamicPasswordExpired = 0x08,
    NoData = 0x09,
    NoPower = 0x0A,
    KeyFlagInvalid = 0x0D,
    CredentialNotFound = 0x1A,
};

const char* lockErrorName(uint8_t code);

}
