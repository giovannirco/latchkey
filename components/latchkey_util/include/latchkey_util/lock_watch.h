// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace latchkey_util {

inline constexpr size_t kWatchStateSize = 22;

struct WatchState {
    bool baselined = false;
    uint16_t cursor = 0;
    bool clockKnown = false;
    int32_t clockOffset = 0;
    uint32_t clockSetUtc = 0;
    uint32_t lastUtc = 0;
    int32_t previousOffset = 0;
    uint16_t offsetSince = 0;

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

void clockSet(WatchState& state, int32_t offset, int64_t utc);

int32_t recordOffset(const WatchState& state, uint16_t seq, int32_t unknownOffset);

}
