// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "latchkey_util/lock_watch.h"
#include "latchkey_util/unlock_alert.h"
#include "latchkey_util/unlock_ledger.h"
#include "ttlock/commands.h"

namespace latchkey_util {

struct PageJudgement {
    std::vector<size_t> fresh;
    std::vector<UnlockFinding> findings;
    bool more = false;
};

class LogWatch {
public:
    LogWatch(size_t capacity, int64_t keepSeconds);

    WatchState& state();
    const WatchState& state() const;

    void noteUnlock(int64_t fromUtc, int64_t toUtc, std::optional<uint32_t> recordId);

    PageJudgement readPage(const ttlock::LogPage& page, int32_t unknownOffset, uint32_t toleranceSeconds,
                           int64_t nowUtc);

    size_t unlocks() const;

private:
    WatchState state_;
    UnlockLedger ledger_;
};

}
