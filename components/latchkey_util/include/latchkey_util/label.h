// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace latchkey_util {

bool normalizeLabel(std::string_view input, size_t maxCodePoints, std::string& out);

}
