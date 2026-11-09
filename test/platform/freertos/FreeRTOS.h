// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

using BaseType_t = int;
using UBaseType_t = unsigned;
using TickType_t = uint32_t;
inline constexpr BaseType_t pdTRUE = 1, pdPASS = 1;
inline constexpr TickType_t portMAX_DELAY = UINT32_MAX;
constexpr TickType_t pdMS_TO_TICKS(uint32_t value) { return value; }
