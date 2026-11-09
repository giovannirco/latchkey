// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/watch_schedule.h"

namespace latchkey_util {

bool canWatchWithoutLink(int64_t lastAdvertMs, int64_t nowMs, int64_t maximumAgeMs) {
    return lastAdvertMs >= 0 && lastAdvertMs <= nowMs && nowMs - lastAdvertMs <= maximumAgeMs;
}

WatchSchedule::WatchSchedule(int64_t intervalMs, int64_t retryMs, int64_t gapMs)
    : intervalMs_(intervalMs), retryMs_(retryMs), gapMs_(gapMs) {}

void WatchSchedule::begin(size_t index, int64_t nowMs, int64_t firstMs, int64_t spreadMs) {
    nextMs_ = nowMs + firstMs + static_cast<int64_t>(index) * spreadMs;
    lastMs_ = -1;
    failed_ = false;
    wanted_ = false;
}

bool WatchSchedule::due(int64_t nowMs) const { return nowMs >= nextMs_; }

bool WatchSchedule::dueWithLink(int64_t nowMs) const {
    if (due(nowMs)) {
        return true;
    }
    return !failed_ && (wanted_ || lastMs_ < 0 || nowMs - lastMs_ >= gapMs_);
}

void WatchSchedule::attempted(int64_t nowMs, bool answered) {
    lastMs_ = nowMs;
    failed_ = !answered;
    nextMs_ = nowMs + (answered ? intervalMs_ : retryMs_);
    if (answered) {
        wanted_ = false;
    }
}

void WatchSchedule::unlocked() { wanted_ = true; }

void WatchSchedule::more() {
    if (lastMs_ >= 0 && nextMs_ > lastMs_) {
        nextMs_ = lastMs_;
    }
}

int64_t WatchSchedule::dueAtMs() const { return nextMs_; }

}
