// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/lock_watch.h"

#include "big_endian.h"

namespace latchkey_util {

namespace {

constexpr uint8_t kVersion = 1;
constexpr uint8_t kBaselined = 0x01;
constexpr uint8_t kClockKnown = 0x02;
constexpr uint8_t kKnownFlags = kBaselined | kClockKnown;

}

std::array<uint8_t, kWatchStateSize> encodeWatchState(const WatchState& state) {
    std::array<uint8_t, kWatchStateSize> out{};
    out[0] = kVersion;
    out[1] = static_cast<uint8_t>((state.baselined ? kBaselined : 0) | (state.clockKnown ? kClockKnown : 0));
    big_endian::write(out.data() + 2, state.cursor, 2);
    big_endian::write(out.data() + 4, static_cast<uint32_t>(state.clockOffset), 4);
    big_endian::write(out.data() + 8, state.clockSetUtc, 4);
    return out;
}

bool decodeWatchState(const uint8_t* data, size_t size, WatchState& out) {
    if (data == nullptr || size != kWatchStateSize || data[0] != kVersion || (data[1] & ~kKnownFlags) != 0) {
        return false;
    }
    WatchState state;
    state.baselined = (data[1] & kBaselined) != 0;
    state.clockKnown = (data[1] & kClockKnown) != 0;
    state.cursor = static_cast<uint16_t>(big_endian::read(data + 2, 2));
    state.clockOffset = static_cast<int32_t>(static_cast<uint32_t>(big_endian::read(data + 4, 4)));
    state.clockSetUtc = static_cast<uint32_t>(big_endian::read(data + 8, 4));
    out = state;
    return true;
}

ClockSync clockSyncNeeded(const WatchState& state, int32_t currentOffset, int64_t nowUtc, int64_t driftSeconds) {
    if (!state.clockKnown || state.clockOffset != currentOffset) {
        return ClockSync::Now;
    }
    const int64_t age = nowUtc - static_cast<int64_t>(state.clockSetUtc);
    return age < 0 || age >= driftSeconds ? ClockSync::Soon : ClockSync::None;
}

}
