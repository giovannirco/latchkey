// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <string_view>

namespace latchkey_util {

bool jsonNestingWithin(std::string_view text, size_t maxDepth);

}
