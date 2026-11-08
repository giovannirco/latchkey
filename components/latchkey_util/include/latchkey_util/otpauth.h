// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace latchkey_util {

std::string otpauthUri(std::string_view account, const uint8_t* secret, size_t length);

}
