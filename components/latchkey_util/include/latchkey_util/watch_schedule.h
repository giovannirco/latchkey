// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>

namespace latchkey_util {

class WatchSchedule {
public:
    WatchSchedule(int64_t intervalMs, int64_t retryMs, int64_t gapMs);

    void begin(size_t index, int64_t nowMs, int64_t firstMs, int64_t spreadMs);

    bool due(int64_t nowMs) const;

    bool dueWithLink(int64_t nowMs) const;

    void attempted(int64_t nowMs, bool answered);

    void unlocked();

    void more();

    int64_t dueAtMs() const;

private:
    int64_t intervalMs_;
    int64_t retryMs_;
    int64_t gapMs_;
    int64_t nextMs_ = 0;
    int64_t lastMs_ = -1;
    bool failed_ = false;
    bool wanted_ = false;
};

}
