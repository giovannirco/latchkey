// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>

#include "latchkey_util/hmac_sha256.h"
#include "latchkey_util/totp.h"

namespace hmac {

bool sha1(const uint8_t* key, size_t keyLength, const uint8_t* message, size_t messageLength,
          uint8_t (&digest)[latchkey_util::kHmacSha1Size]);

bool sha256(const uint8_t* key, size_t keyLength, const uint8_t* message, size_t messageLength,
            uint8_t (&digest)[latchkey_util::kHmacSha256Size]);

}
