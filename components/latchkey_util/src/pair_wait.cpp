// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/pair_wait.h"

namespace latchkey_util {

namespace {

constexpr uint32_t kSerialPairWaitSeconds = 30;
constexpr uint32_t kWebPairWaitSeconds = 120;

}

uint32_t defaultPairWaitSeconds(bool serial) { return serial ? kSerialPairWaitSeconds : kWebPairWaitSeconds; }

}
