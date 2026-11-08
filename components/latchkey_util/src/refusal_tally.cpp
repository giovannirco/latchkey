// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/refusal_tally.h"

namespace latchkey_util {

RefusalTally::RefusalTally(int64_t windowMs) : windowMs_(windowMs) {}

void RefusalTally::note(std::string_view kind, uint32_t count) {
    for (Entry& entry : entries_) {
        if (entry.kind == kind) {
            entry.pending += count;
            return;
        }
    }
    Entry entry;
    entry.kind = std::string(kind);
    entry.pending = count;
    entries_.push_back(std::move(entry));
}

std::vector<RefusalCount> RefusalTally::due(int64_t nowMs) {
    std::vector<RefusalCount> counts;
    for (Entry& entry : entries_) {
        if (entry.pending == 0 || (entry.reported && nowMs - entry.reportedMs < windowMs_)) {
            continue;
        }
        counts.push_back(RefusalCount{entry.kind, entry.pending});
        entry.pending = 0;
        entry.reported = true;
        entry.reportedMs = nowMs;
    }
    return counts;
}

}
