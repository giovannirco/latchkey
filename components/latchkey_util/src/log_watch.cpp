// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/log_watch.h"

#include "latchkey_util/lock_log.h"

namespace latchkey_util {

LogWatch::LogWatch(size_t capacity, int64_t keepSeconds) : ledger_(capacity, keepSeconds) {}

WatchState& LogWatch::state() { return state_; }

const WatchState& LogWatch::state() const { return state_; }

void LogWatch::noteUnlock(int64_t fromUtc, int64_t toUtc, std::optional<uint32_t> recordId) {
    ledger_.note(fromUtc, toUtc, recordId);
}

PageJudgement LogWatch::readPage(const ttlock::LogPage& page, int32_t unknownOffset, uint32_t toleranceSeconds,
                                 int64_t nowUtc) {
    const int32_t offset = state_.clockKnown ? state_.clockOffset : unknownOffset;
    const LogStep step = stepLog(state_, page, offset);
    PageJudgement judged;
    judged.fresh = step.fresh;
    judged.more = step.more;
    if (step.fresh.empty()) {
        return judged;
    }
    std::vector<ttlock::LogEntry> entries;
    entries.reserve(step.fresh.size());
    for (const size_t index : step.fresh) {
        ttlock::LogEntry entry;
        entry.recordNumber = page.entries[index].recordNumber;
        entry.type = page.entries[index].type;
        entry.time = page.entries[index].time;
        entry.recordId = page.entries[index].recordId;
        entries.push_back(entry);
    }
    judged.findings = ledger_.judge(entries, offset, toleranceSeconds, nowUtc);
    state_ = step.state;
    return judged;
}

size_t LogWatch::unlocks() const { return ledger_.size(); }

}
