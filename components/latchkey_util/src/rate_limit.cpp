// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/rate_limit.h"

namespace latchkey_util {

namespace {

constexpr int64_t kMillisecondsPerSecond = 1000;
constexpr uint32_t kMaxDoublings = 32;

}

RateLimiter::RateLimiter(const Policy& policy) : policy_(policy), saturation_(policy.failuresBeforeWait) {
    while (saturation_ < policy_.failuresBeforeWait + kMaxDoublings &&
           waitSeconds(saturation_) < policy_.maxWaitSeconds) {
        ++saturation_;
    }
}

void RateLimiter::restore(uint32_t failures, int64_t nowMs) {
    failures_ = failures < saturation_ ? failures : saturation_;
    const uint32_t wait = waitSeconds(failures_);
    blockedUntilMs_ = wait > 0 ? nowMs + static_cast<int64_t>(wait) * kMillisecondsPerSecond : 0;
}

uint32_t RateLimiter::retryAfterSeconds(int64_t nowMs) const {
    if (nowMs >= blockedUntilMs_) {
        return 0;
    }
    return static_cast<uint32_t>((blockedUntilMs_ - nowMs + kMillisecondsPerSecond - 1) / kMillisecondsPerSecond);
}

bool RateLimiter::recordFailure(int64_t nowMs) {
    const bool changed = failures_ < saturation_;
    if (changed) {
        ++failures_;
    }
    const uint32_t wait = waitSeconds(failures_);
    if (wait > 0) {
        blockedUntilMs_ = nowMs + static_cast<int64_t>(wait) * kMillisecondsPerSecond;
    }
    return changed;
}

bool RateLimiter::recordSuccess() {
    const bool changed = failures_ != 0;
    failures_ = 0;
    blockedUntilMs_ = 0;
    return changed;
}

uint32_t RateLimiter::failures() const { return failures_; }

uint32_t RateLimiter::waitSeconds(uint32_t failures) const {
    if (failures < policy_.failuresBeforeWait) {
        return 0;
    }
    const uint32_t doublings = failures - policy_.failuresBeforeWait;
    if (doublings >= kMaxDoublings) {
        return policy_.maxWaitSeconds;
    }
    const uint64_t wait = static_cast<uint64_t>(policy_.firstWaitSeconds) << doublings;
    return wait >= policy_.maxWaitSeconds ? policy_.maxWaitSeconds : static_cast<uint32_t>(wait);
}

}
