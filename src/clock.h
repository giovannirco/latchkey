// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace wallclock {

inline constexpr int64_t kMinUtc = 1704067200;
inline constexpr int64_t kMaxUtc = 4102444800;

void init();

bool synced();

int64_t utcSeconds();

bool set(int64_t utc);

}
