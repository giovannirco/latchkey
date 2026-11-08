// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/connection_backoff.h"

namespace latchkey_util {

ConnectionBackoff::ConnectionBackoff(const RateLimiter::Policy& policy, int64_t stableMs)
    : limiter_(policy), stableMs_(stableMs) {}

void ConnectionBackoff::connected(int64_t nowMs) { connectedMs_ = nowMs; }

void ConnectionBackoff::disconnected(int64_t nowMs) {
    if (connectedMs_.has_value() && nowMs - *connectedMs_ >= stableMs_) {
        limiter_.recordSuccess();
    }
    connectedMs_.reset();
    limiter_.recordFailure(nowMs);
}

void ConnectionBackoff::reset() {
    limiter_.recordSuccess();
    connectedMs_.reset();
}

uint32_t ConnectionBackoff::retryAfterSeconds(int64_t nowMs) const { return limiter_.retryAfterSeconds(nowMs); }

}
