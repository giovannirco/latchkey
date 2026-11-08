// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/pair_verdict.h"

#include <cstdio>

namespace latchkey_util {

PairVerdict judgePairing(PairEnd end, bool keysStored, bool resultStored) {
    switch (end) {
        case PairEnd::Paired:
            if (resultStored) {
                return PairVerdict::Paired;
            }
            return keysStored ? PairVerdict::Incomplete : PairVerdict::KeysNotStored;
        case PairEnd::Incomplete:
            return keysStored ? PairVerdict::Incomplete : PairVerdict::KeysNotStored;
        case PairEnd::Failed:
            break;
    }
    return PairVerdict::Failed;
}

bool answeredAsAnotherLockType(ttlock::Status status, size_t mismatchesBefore, size_t mismatchesAfter) {
    return status == ttlock::Status::Unsupported && mismatchesAfter > mismatchesBefore;
}

std::string lockTypeMismatch(const ttlock::LockVersion& answered, const ttlock::LockVersion& advertised) {
    char message[160];
    std::snprintf(message, sizeof(message),
                  "the lock answered as lock type %u.%u scene %u, but its advert said %u.%u scene %u: this board "
                  "only pairs the lock type it advertises",
                  static_cast<unsigned>(answered.protocolType), static_cast<unsigned>(answered.protocolVersion),
                  static_cast<unsigned>(answered.scene), static_cast<unsigned>(advertised.protocolType),
                  static_cast<unsigned>(advertised.protocolVersion), static_cast<unsigned>(advertised.scene));
    return message;
}

}
