// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/unlock_ledger.h"

#include <algorithm>

namespace latchkey_util {

UnlockLedger::UnlockLedger(size_t capacity, int64_t keepSeconds) : capacity_(capacity), keepSeconds_(keepSeconds) {}

void UnlockLedger::note(int64_t fromUtc, int64_t toUtc, std::optional<uint32_t> recordId) {
    if (capacity_ == 0) {
        return;
    }
    if (windows_.size() >= capacity_) {
        windows_.erase(windows_.begin());
    }
    LatchkeyUnlock window;
    window.fromUtc = fromUtc;
    window.toUtc = toUtc;
    window.recordId = recordId;
    windows_.push_back(window);
}

std::vector<UnlockFinding> UnlockLedger::judge(const std::vector<ttlock::LogEntry>& entries,
                                               int32_t lockUtcOffsetSeconds, uint32_t toleranceSeconds,
                                               int64_t nowUtc) {
    windows_.erase(std::remove_if(windows_.begin(), windows_.end(),
                                  [this, nowUtc](const LatchkeyUnlock& window) {
                                      return window.toUtc < nowUtc - keepSeconds_;
                                  }),
                   windows_.end());
    std::vector<bool> used;
    std::vector<UnlockFinding> findings =
        classifyUnlocks(entries, windows_, lockUtcOffsetSeconds, toleranceSeconds, used);
    std::vector<LatchkeyUnlock> kept;
    kept.reserve(windows_.size());
    for (size_t i = 0; i < windows_.size(); ++i) {
        if (!used[i]) {
            kept.push_back(windows_[i]);
        }
    }
    windows_ = std::move(kept);
    return findings;
}

size_t UnlockLedger::size() const { return windows_.size(); }

}
