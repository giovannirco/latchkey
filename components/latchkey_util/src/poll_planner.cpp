// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/poll_planner.h"

namespace latchkey_util {

PollPlanner::PollPlanner(int64_t intervalMs, int64_t retryMs, int64_t gapMs)
    : intervalMs_(intervalMs), retryMs_(retryMs), gapMs_(gapMs) {}

void PollPlanner::track(const std::string& lock) { schedules_.try_emplace(lock, intervalMs_, retryMs_); }

void PollPlanner::forget(const std::string& lock) { schedules_.erase(lock); }

std::optional<std::string> PollPlanner::next(int64_t nowMs, bool queueIdle) const {
    if (running_.has_value() || !queueIdle || nowMs < quietUntilMs_) {
        return std::nullopt;
    }
    std::optional<std::string> chosen;
    int64_t earliest = 0;
    for (const auto& [lock, schedule] : schedules_) {
        if (schedule.due(nowMs) && (!chosen.has_value() || schedule.dueAtMs() < earliest)) {
            chosen = lock;
            earliest = schedule.dueAtMs();
        }
    }
    return chosen;
}

void PollPlanner::started(const std::string& lock) { running_ = lock; }

void PollPlanner::finished(const std::string& lock, int64_t nowMs, bool answered) {
    if (running_ == lock) {
        running_.reset();
        quietUntilMs_ = nowMs + gapMs_;
    }
    const auto schedule = schedules_.find(lock);
    if (schedule != schedules_.end()) {
        schedule->second.attempted(nowMs, answered);
    }
}

void PollPlanner::refreshed(const std::string& lock, int64_t nowMs) {
    const auto schedule = schedules_.find(lock);
    if (schedule != schedules_.end()) {
        schedule->second.refreshed(nowMs);
    }
}

}
