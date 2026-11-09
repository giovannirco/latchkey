// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <string_view>

namespace latchkey_util {

inline constexpr size_t kMaxHostname = 64;

bool isHostname(std::string_view host);

}
