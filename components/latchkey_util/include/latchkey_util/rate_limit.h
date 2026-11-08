// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace latchkey_util {

class RateLimiter {
public:
    struct Policy {
        uint32_t failuresBeforeWait;
        uint32_t firstWaitSeconds;
        uint32_t maxWaitSeconds;
    };

    explicit RateLimiter(const Policy& policy);

    void restore(uint32_t failures, int64_t nowMs);

    uint32_t retryAfterSeconds(int64_t nowMs) const;

    bool recordFailure(int64_t nowMs);

    bool recordSuccess();

    uint32_t failures() const;

private:
    uint32_t waitSeconds(uint32_t failures) const;

    Policy policy_;
    uint32_t saturation_;
    uint32_t failures_ = 0;
    int64_t blockedUntilMs_ = 0;
};

}
