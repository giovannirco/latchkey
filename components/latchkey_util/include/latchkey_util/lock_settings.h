// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "ttlock/types.h"

namespace latchkey_util {

inline constexpr uint32_t kMaxAutolockSeconds = 0xFFFF;

bool passageTypeOf(std::string_view name, ttlock::PassageType& out);

const char* passageTypeName(ttlock::PassageType type);

bool makePassage(ttlock::PassageType type, int day, std::string_view start, std::string_view end,
                 ttlock::PassageMode& out);

bool runsForward(const ttlock::PassageMode& mode);

std::string passageListJson(const std::vector<ttlock::PassageMode>& modes);

std::string passageAddStopped(std::string_view failure, size_t added);

bool autolockAllowed(uint32_t seconds, const ttlock::AutoLockSetting& range);

std::string autolockJson(const ttlock::AutoLockSetting& setting);

}
