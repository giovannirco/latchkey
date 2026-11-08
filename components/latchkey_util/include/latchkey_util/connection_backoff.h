// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>

#include "latchkey_util/rate_limit.h"

namespace latchkey_util {

class ConnectionBackoff {
public:
    ConnectionBackoff(const RateLimiter::Policy& policy, int64_t stableMs);

    void connected(int64_t nowMs);

    void disconnected(int64_t nowMs);

    void reset();

    uint32_t retryAfterSeconds(int64_t nowMs) const;

private:
    RateLimiter limiter_;
    int64_t stableMs_;
    std::optional<int64_t> connectedMs_;
};

}
