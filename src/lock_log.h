// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "cJSON.h"
#include "latchkey_util/lock_watch.h"
#include "latchkey_util/unlock_ledger.h"
#include "ttlock/session.h"
#include "ttlock/types.h"

namespace lock_log {

inline constexpr size_t kPagesPerRead = 8;
inline constexpr uint16_t kShownSlots = 16;
inline constexpr uint32_t kToleranceSeconds = 120;

class Entries {
public:
    Entries() = default;
    Entries(const Entries&) = delete;
    Entries& operator=(const Entries&) = delete;
    ~Entries();

    bool has(uint16_t seq) const;
    void add(ttlock::LogEntry& entry);
    const std::vector<ttlock::LogEntry>& items() const { return items_; }

private:
    std::vector<ttlock::LogEntry> items_;
};

ttlock::Status findEnd(ttlock::Session& session, int32_t offset, latchkey_util::WatchState& state);

ttlock::Status catchUp(ttlock::Session& session, int32_t offset, latchkey_util::WatchState& state, Entries& fresh,
                       bool& more);

ttlock::Status readSlots(ttlock::Session& session, uint16_t from, uint16_t to, Entries& out);

void judge(const std::string& mac, const Entries& fresh, latchkey_util::UnlockLedger& ledger, int32_t offset,
           int64_t nowUtc);

cJSON* fetchResult(const Entries& entries, std::optional<uint16_t> since, bool more, int32_t offset);

}
