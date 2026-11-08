// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>

namespace latchkey_util {

inline constexpr size_t kHmacSha256Size = 32;

using HmacSha256 = bool (*)(const uint8_t* key, size_t keyLength, const uint8_t* message, size_t messageLength,
                            uint8_t (&digest)[kHmacSha256Size]);

using KeyedHmacSha256 =
    std::function<bool(const uint8_t* message, size_t messageLength, uint8_t (&digest)[kHmacSha256Size])>;

}
