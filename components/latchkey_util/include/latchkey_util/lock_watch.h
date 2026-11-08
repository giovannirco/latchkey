// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace latchkey_util {

inline constexpr size_t kWatchStateSize = 12;

struct WatchState {
    bool baselined = false;
    uint16_t cursor = 0;
    bool clockKnown = false;
    int32_t clockOffset = 0;
    uint32_t clockSetUtc = 0;

    bool operator==(const WatchState&) const = default;
};

enum class ClockSync : uint8_t {
    None,
    Soon,
    Now,
};

std::array<uint8_t, kWatchStateSize> encodeWatchState(const WatchState& state);

bool decodeWatchState(const uint8_t* data, size_t size, WatchState& out);

ClockSync clockSyncNeeded(const WatchState& state, int32_t currentOffset, int64_t nowUtc, int64_t driftSeconds);

}
