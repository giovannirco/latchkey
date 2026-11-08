// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/passcode_id.h"

#include <algorithm>

namespace latchkey_util {

namespace {

constexpr char kIdKeyLabel[] = "latchkey passcode id v1";

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

}
