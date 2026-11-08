// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace latchkey_util {

inline constexpr uint64_t kMaxFingerprintId = (uint64_t{1} << 48) - 1;
inline constexpr uint64_t kMaxCardNumber = UINT64_MAX;

bool parseCredentialId(std::string_view text, uint64_t maximum, uint64_t& out);

std::string formatCredentialId(uint64_t id);

}
