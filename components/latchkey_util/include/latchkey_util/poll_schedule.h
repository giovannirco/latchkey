// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace latchkey_util {

class PollSchedule {
public:
    PollSchedule(int64_t intervalMs, int64_t retryMs);

    bool due(int64_t nowMs) const;

    void attempted(int64_t nowMs, bool answered);

    void refreshed(int64_t nowMs);

private:
    int64_t intervalMs_;
    int64_t retryMs_;
    int64_t nextMs_ = 0;
};

}
