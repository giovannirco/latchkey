// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/lock_watch.h"

#include "big_endian.h"

namespace latchkey_util {

namespace {

constexpr uint8_t kFirstVersion = 1;
constexpr uint8_t kVersion = 2;
constexpr size_t kFirstSize = 16;
constexpr uint8_t kBaselined = 0x01;
constexpr uint8_t kClockKnown = 0x02;
constexpr uint8_t kKnownFlags = kBaselined | kClockKnown;

int32_t readSigned(const uint8_t* data) { return static_cast<int32_t>(static_cast<uint32_t>(big_endian::read(data, 4))); }

}

std::array<uint8_t, kWatchStateSize> encodeWatchState(const WatchState& state) {
    std::array<uint8_t, kWatchStateSize> out{};
    out[0] = kVersion;
    out[1] = static_cast<uint8_t>((state.baselined ? kBaselined : 0) | (state.clockKnown ? kClockKnown : 0));
    big_endian::write(out.data() + 2, state.cursor, 2);
    big_endian::write(out.data() + 4, static_cast<uint32_t>(state.clockOffset), 4);
    big_endian::write(out.data() + 8, state.clockSetUtc, 4);
    big_endian::write(out.data() + 12, state.lastUtc, 4);
    big_endian::write(out.data() + 16, static_cast<uint32_t>(state.previousOffset), 4);
    big_endian::write(out.data() + 20, state.offsetSince, 2);
    return out;
}

bool decodeWatchState(const uint8_t* data, size_t size, WatchState& out) {
    if (data == nullptr || size < kFirstSize) {
        return false;
    }
    const bool first = data[0] == kFirstVersion && size == kFirstSize;
    const bool current = data[0] == kVersion && size == kWatchStateSize;
    if ((!first && !current) || (data[1] & ~kKnownFlags) != 0) {
        return false;
    }
    WatchState state;
    state.baselined = (data[1] & kBaselined) != 0;
    state.clockKnown = (data[1] & kClockKnown) != 0;
    state.cursor = static_cast<uint16_t>(big_endian::read(data + 2, 2));
    state.clockOffset = readSigned(data + 4);
    state.clockSetUtc = static_cast<uint32_t>(big_endian::read(data + 8, 4));
    state.lastUtc = static_cast<uint32_t>(big_endian::read(data + 12, 4));
    state.previousOffset = current ? readSigned(data + 16) : state.clockOffset;
    state.offsetSince = current ? static_cast<uint16_t>(big_endian::read(data + 20, 2)) : 0;
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

void clockSet(WatchState& state, int32_t offset, int64_t utc) {
    if (!state.clockKnown || state.clockOffset != offset) {
        state.previousOffset = state.clockKnown ? state.clockOffset : offset;
        state.offsetSince = state.cursor;
    }
    state.clockKnown = true;
    state.clockOffset = offset;
    state.clockSetUtc = static_cast<uint32_t>(utc);
}

int32_t recordOffset(const WatchState& state, uint16_t seq, int32_t unknownOffset) {
    if (!state.clockKnown) {
        return unknownOffset;
    }
    return seq < state.offsetSince ? state.previousOffset : state.clockOffset;
}

}
