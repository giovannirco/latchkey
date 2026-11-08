// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "latchkey_util/unlock_alert.h"
#include "ttlock/types.h"

namespace latchkey_util {

class UnlockLedger {
public:
    UnlockLedger(size_t capacity, int64_t keepSeconds);

    void note(int64_t fromUtc, int64_t toUtc, std::optional<uint32_t> recordId = std::nullopt);

    std::vector<UnlockFinding> judge(const std::vector<ttlock::LogEntry>& entries, int32_t lockUtcOffsetSeconds,
                                     uint32_t toleranceSeconds, int64_t nowUtc);

    size_t size() const;

private:
    std::vector<LatchkeyUnlock> windows_;
    size_t capacity_;
    int64_t keepSeconds_;
};

}
