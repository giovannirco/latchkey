// SPDX-License-Identifier: GPL-3.0-or-later
// A record id, when the unlock reply carries one, explains the log entry with that id whatever its time; a window
// explains the rest.
#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "ttlock/types.h"

namespace latchkey_util {

enum class UnlockMethod : uint8_t {
    None,
    App,
    Remote,
    Passcode,
    Fingerprint,
    Card,
    MechanicalKey,
    Wristband,
    Forced,
    Other,
};

enum class UnlockVerdict : uint8_t {
    NotUnlock,
    Latchkey,
    Alert,
    Reported,
};

struct LatchkeyUnlock {
    int64_t fromUtc = 0;
    int64_t toUtc = 0;
    UnlockMethod method = UnlockMethod::App;
    std::optional<uint32_t> recordId;
};

struct UnlockFinding {
    UnlockMethod method = UnlockMethod::None;
    UnlockVerdict verdict = UnlockVerdict::NotUnlock;
};

UnlockMethod unlockMethodOf(uint8_t recordType);

const char* toString(UnlockMethod method);

std::vector<UnlockFinding> classifyUnlocks(const std::vector<ttlock::LogEntry>& entries,
                                           const std::vector<LatchkeyUnlock>& performed, int32_t lockUtcOffsetSeconds,
                                           uint32_t toleranceSeconds);

std::vector<UnlockFinding> classifyUnlocks(const std::vector<ttlock::LogEntry>& entries,
                                           const std::vector<LatchkeyUnlock>& performed, int32_t lockUtcOffsetSeconds,
                                           uint32_t toleranceSeconds, std::vector<bool>& used);

}
