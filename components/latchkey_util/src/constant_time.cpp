// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/constant_time.h"

namespace latchkey_util {

bool constantTimeEqual(const uint8_t* a, const uint8_t* b, size_t length) {
    volatile uint8_t difference = 0;
    for (size_t i = 0; i < length; ++i) {
        difference = static_cast<uint8_t>(difference | (a[i] ^ b[i]));
    }
    return difference == 0;
}

}
