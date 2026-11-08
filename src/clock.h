// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "esp_err.h"

namespace wallclock {

inline constexpr int64_t kMinUtc = 1704067200;
inline constexpr int64_t kMaxUtc = 4102444800;

void init();

bool synced();

int64_t utcSeconds();

bool set(int64_t utc);

std::string timezone();

esp_err_t setTimezone(std::string_view timezone);

int32_t utcOffsetAt(int64_t utc);

int32_t utcOffsetSeconds();

}
