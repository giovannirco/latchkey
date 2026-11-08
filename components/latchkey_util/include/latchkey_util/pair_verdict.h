// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace latchkey_util {

enum class PairEnd : uint8_t {
    Paired,
    Incomplete,
    Failed,
};

enum class PairVerdict : uint8_t {
    Paired,
    Incomplete,
    KeysNotStored,
    Failed,
};

PairVerdict judgePairing(PairEnd end, bool keysStored, bool resultStored);

}
