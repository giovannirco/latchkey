// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace latchkey_util {

inline constexpr size_t kHmacSha1Size = 20;
inline constexpr int64_t kTotpStepSeconds = 30;

using HmacSha1 = bool (*)(const uint8_t* key, size_t keyLength, const uint8_t* message, size_t messageLength,
                          uint8_t (&digest)[kHmacSha1Size]);

enum class TotpVerdict : uint8_t {
    Accepted,
    Rejected,
    HmacFailed,
};

uint64_t totpStep(int64_t unixSeconds);

bool totpCode(const uint8_t* secret, size_t secretLength, uint64_t step, HmacSha1 hmac, uint32_t& code);

TotpVerdict totpVerify(const uint8_t* secret, size_t secretLength, int64_t unixSeconds, uint32_t code,
                       uint64_t lastStep, HmacSha1 hmac, uint64_t& acceptedStep);

bool parseTotpCode(std::string_view text, uint32_t& code);

}
