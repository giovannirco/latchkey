// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/pair_verdict.h"

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

}
