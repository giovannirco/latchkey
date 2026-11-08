// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string_view>

#include "ttlock/types.h"

namespace latchkey_util {

const char* passcodeTypeName(ttlock::PasscodeType type);

bool passcodeTypeOf(std::string_view name, ttlock::PasscodeType& out);

}
