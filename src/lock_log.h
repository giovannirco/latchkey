// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "cJSON.h"
#include "latchkey_util/log_watch.h"
#include "rpc.h"
#include "store.h"
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

ttlock::Status catchUp(ttlock::Session& session, const std::string& mac, int32_t offset,
                       latchkey_util::LogWatch& watch, Entries& fresh, bool& more, int64_t nowUtc,
                       bool stopOnFailure = false);

ttlock::Status readSlots(ttlock::Session& session, uint16_t from, uint16_t to, Entries& out);

rpc::Reply fetchResult(const Entries& entries, std::optional<uint16_t> since, uint32_t until, bool more,
                        const latchkey_util::WatchState& state, int32_t offset, const store::locks::Record& record);

}
