// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "latchkey_util/lock_watch.h"
#include "ttlock/commands.h"
#include "ttlock/types.h"

namespace latchkey_util {

inline constexpr uint16_t kLastLogSlot = 0xFFFE;

struct LogStep {
    std::vector<size_t> fresh;
    WatchState state;
    bool more = false;
};

std::string logEntriesJson(const std::vector<ttlock::LogEntry>& entries, int32_t lockUtcOffsetSeconds);

std::string logEntriesJson(const std::vector<ttlock::LogEntry>& entries, const WatchState& state,
                           int32_t unknownOffset);

LogStep stepLog(const WatchState& state, const ttlock::LogPage& page, int32_t lockUtcOffsetSeconds);

class LogEndSearch {
public:
    bool done() const;

    uint16_t slot() const;

    void read(const ttlock::LogPage& page, int32_t lockUtcOffsetSeconds);

    WatchState baseline(const WatchState& state) const;

    size_t reads() const;

private:
    int32_t low_ = 0;
    int32_t high_ = kLastLogSlot;
    uint16_t cursor_ = 0;
    uint32_t lastUtc_ = 0;
    size_t reads_ = 0;
};

}
