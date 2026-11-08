// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/password_record.h"

#include <algorithm>

namespace latchkey_util {

namespace {

constexpr size_t kSaltOffset = 1;
constexpr size_t kIterationsOffset = kSaltOffset + kPasswordSaltSize;
constexpr size_t kHashOffset = kIterationsOffset + sizeof(uint32_t);

}

PasswordRecordBytes encodePasswordRecord(const PasswordRecord& record) {
    PasswordRecordBytes bytes{};
    bytes[0] = kPasswordRecordVersion;
    std::copy(record.salt.begin(), record.salt.end(), bytes.begin() + kSaltOffset);
    for (size_t i = 0; i < sizeof(uint32_t); ++i) {
        bytes[kIterationsOffset + i] = static_cast<uint8_t>(record.iterations >> (8 * i));
    }
    std::copy(record.hash.begin(), record.hash.end(), bytes.begin() + kHashOffset);
    return bytes;
}

bool decodePasswordRecord(const uint8_t* data, size_t length, PasswordRecord& out) {
    if (length != kPasswordRecordSize || data[0] != kPasswordRecordVersion) {
        return false;
    }
    PasswordRecord record;
    std::copy(data + kSaltOffset, data + kIterationsOffset, record.salt.begin());
    for (size_t i = 0; i < sizeof(uint32_t); ++i) {
        record.iterations |= static_cast<uint32_t>(data[kIterationsOffset + i]) << (8 * i);
    }
    std::copy(data + kHashOffset, data + kPasswordRecordSize, record.hash.begin());
    if (record.iterations == 0) {
        return false;
    }
    out = record;
    return true;
}

}
