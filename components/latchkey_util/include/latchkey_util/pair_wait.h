// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace latchkey_util {

constexpr uint32_t kMaxPairWaitSeconds = 600;

uint32_t defaultPairWaitSeconds(bool serial);

}
