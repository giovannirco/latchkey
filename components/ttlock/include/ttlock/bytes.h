// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstdint>
#include <vector>

namespace ttlock {

using Bytes = std::vector<uint8_t>;
using AesKey = std::array<uint8_t, 16>;

}
