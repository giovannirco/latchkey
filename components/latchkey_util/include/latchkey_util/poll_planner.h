// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>

#include "latchkey_util/poll_schedule.h"

namespace latchkey_util {

class PollPlanner {
public:
    PollPlanner(int64_t intervalMs, int64_t retryMs, int64_t gapMs);

    void track(const std::string& lock);

    void forget(const std::string& lock);

    std::optional<std::string> next(int64_t nowMs, bool queueIdle) const;

    void started(const std::string& lock);

    void finished(const std::string& lock, int64_t nowMs, bool answered);

    void refreshed(const std::string& lock, int64_t nowMs);

private:
    int64_t intervalMs_;
    int64_t retryMs_;
    int64_t gapMs_;
    std::map<std::string, PollSchedule> schedules_;
    std::optional<std::string> running_;
    int64_t quietUntilMs_ = 0;
};

}
