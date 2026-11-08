// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/debounce.h"

namespace latchkey_util {

Debouncer::Debouncer(uint8_t stableSamples) : stableSamples_(stableSamples) {}

bool Debouncer::update(bool active) {
    if (active == pressed_) {
        run_ = 0;
        return false;
    }
    if (++run_ < stableSamples_) {
        return false;
    }
    run_ = 0;
    pressed_ = active;
    return pressed_;
}

bool Debouncer::pressed() const { return pressed_; }

}
