// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>

#include "latchkey_util/hmac_sha256.h"

namespace latchkey_util {

using Pbkdf2Yield = std::function<void()>;

bool pbkdf2HmacSha256(const KeyedHmacSha256& passwordHmac, const uint8_t* salt, size_t saltLength, uint32_t iterations,
                      uint32_t yieldEvery, const Pbkdf2Yield& yield, uint8_t* out, size_t outLength);

}
