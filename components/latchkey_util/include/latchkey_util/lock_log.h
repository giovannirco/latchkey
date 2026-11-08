// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "ttlock/types.h"

namespace latchkey_util {

std::string logEntriesJson(const std::vector<ttlock::LogEntry>& entries, int32_t lockUtcOffsetSeconds);

}
