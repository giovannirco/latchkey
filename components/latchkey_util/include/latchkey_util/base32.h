// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace latchkey_util {

std::string base32Encode(const uint8_t* data, size_t length);

}
