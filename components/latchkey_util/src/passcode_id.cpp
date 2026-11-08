// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/passcode_id.h"

#include <algorithm>

namespace latchkey_util {

namespace {

constexpr char kIdKeyLabel[] = "latchkey passcode id v1";
constexpr char kHexDigits[] = "0123456789abcdef";

int hexValue(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

struct Digest {
    uint8_t bytes[kHmacSha256Size] = {};

    ~Digest() {
        volatile uint8_t* wiped = bytes;
        for (size_t i = 0; i < sizeof(bytes); ++i) {
            wiped[i] = 0;
        }
    }
};

}

bool passcodeId(const LockAesKey& lockKey, std::string_view code, HmacSha256 hmac, PasscodeId& out) {
    if (hmac == nullptr || code.empty()) {
        return false;
    }
    Digest idKey;
    if (!hmac(lockKey.data(), lockKey.size(), reinterpret_cast<const uint8_t*>(kIdKeyLabel), sizeof(kIdKeyLabel) - 1,
              idKey.bytes)) {
        return false;
    }
    Digest mac;
    if (!hmac(idKey.bytes, sizeof(idKey.bytes), reinterpret_cast<const uint8_t*>(code.data()), code.size(),
              mac.bytes)) {
        return false;
    }
    std::copy(mac.bytes, mac.bytes + kPasscodeIdSize, out.begin());
    return true;
}

std::string formatPasscodeId(const PasscodeId& id) {
    std::string text(2 * id.size(), '0');
    for (size_t i = 0; i < id.size(); ++i) {
        text[2 * i] = kHexDigits[id[i] >> 4];
        text[2 * i + 1] = kHexDigits[id[i] & 0x0F];
    }
    return text;
}

bool parsePasscodeId(std::string_view text, PasscodeId& out) {
    if (text.size() != 2 * kPasscodeIdSize) {
        return false;
    }
    PasscodeId id{};
    for (size_t i = 0; i < text.size(); ++i) {
        const int nibble = hexValue(text[i]);
        if (nibble < 0) {
            return false;
        }
        id[i / 2] = static_cast<uint8_t>(id[i / 2] << 4 | nibble);
    }
    out = id;
    return true;
}

uint64_t passcodeIdNumber(const PasscodeId& id) {
    uint64_t value = 0;
    for (uint8_t byte : id) {
        value = value << 8 | byte;
    }
    return value;
}

}
