// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>

namespace latchkey_util {

bool constantTimeEqual(const uint8_t* a, const uint8_t* b, size_t length);

}
