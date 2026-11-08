// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/poll_schedule.h"

namespace latchkey_util {

PollSchedule::PollSchedule(int64_t intervalMs, int64_t retryMs) : intervalMs_(intervalMs), retryMs_(retryMs) {}

bool PollSchedule::due(int64_t nowMs) const { return nowMs >= nextMs_; }

void PollSchedule::attempted(int64_t nowMs, bool answered) { nextMs_ = nowMs + (answered ? intervalMs_ : retryMs_); }

void PollSchedule::refreshed(int64_t nowMs) { nextMs_ = nowMs + intervalMs_; }

}
