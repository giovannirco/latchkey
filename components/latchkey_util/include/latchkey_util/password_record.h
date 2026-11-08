// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace latchkey_util {

inline constexpr size_t kPasswordSaltSize = 16;
inline constexpr size_t kPasswordHashSize = 32;
inline constexpr uint8_t kPasswordRecordVersion = 1;
inline constexpr size_t kPasswordRecordSize = 1 + kPasswordSaltSize + sizeof(uint32_t) + kPasswordHashSize;

struct PasswordRecord {
    std::array<uint8_t, kPasswordSaltSize> salt{};
    uint32_t iterations = 0;
    std::array<uint8_t, kPasswordHashSize> hash{};
};

using PasswordRecordBytes = std::array<uint8_t, kPasswordRecordSize>;

PasswordRecordBytes encodePasswordRecord(const PasswordRecord& record);

bool decodePasswordRecord(const uint8_t* data, size_t length, PasswordRecord& out);

}
