// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "latchkey_util/hmac_sha256.h"

namespace latchkey_util {

inline constexpr size_t kPasscodeIdSize = 6;

using PasscodeId = std::array<uint8_t, kPasscodeIdSize>;
using LockAesKey = std::array<uint8_t, 16>;

bool passcodeId(const LockAesKey& lockKey, std::string_view code, HmacSha256 hmac, PasscodeId& out);

}
