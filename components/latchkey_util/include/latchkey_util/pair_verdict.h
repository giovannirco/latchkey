// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "ttlock/frame.h"
#include "ttlock/status.h"

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

bool answeredAsAnotherLockType(ttlock::Status status, size_t mismatchesBefore, size_t mismatchesAfter);

std::string lockTypeMismatch(const ttlock::LockVersion& answered, const ttlock::LockVersion& advertised);

}
