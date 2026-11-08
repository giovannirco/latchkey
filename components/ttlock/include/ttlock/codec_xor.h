// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

#include "ttlock/bytes.h"

namespace ttlock {

Bytes xorCodec(const Bytes& data, uint8_t seed);

}
