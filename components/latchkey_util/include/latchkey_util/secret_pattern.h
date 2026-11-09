// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string_view>

namespace latchkey_util {

bool holdsSecretPattern(std::string_view text);

}
