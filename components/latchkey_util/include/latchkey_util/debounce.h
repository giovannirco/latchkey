// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace latchkey_util {

class Debouncer {
public:
    explicit Debouncer(uint8_t stableSamples);

    bool update(bool active);

    bool pressed() const;

private:
    uint8_t stableSamples_;
    uint8_t run_ = 0;
    bool pressed_ = false;
};

}
