// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "ttlock/bytes.h"

namespace ttlock {

extern const AesKey kDefaultAesKey;

Bytes aesEncrypt(const Bytes& plain, const AesKey& key);
bool aesDecrypt(const Bytes& cipher, const AesKey& key, Bytes& out);

}
