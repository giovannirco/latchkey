// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>

#include "latchkey_util/rate_limit.h"

using latchkey_util::RateLimiter;

void setUp() {}

void tearDown() {}

static constexpr RateLimiter::Policy kPolicy{5, 30, 900};
static constexpr int64_t kSecond = 1000;

static int64_t failUntilBlocked(RateLimiter& limiter, int64_t now) {
    while (limiter.retryAfterSeconds(now) == 0) {
        limiter.recordFailure(now);
    }
    return now;
}

static void test_four_failures_cost_nothing() {
    RateLimiter limiter(kPolicy);
    for (uint32_t i = 1; i <= 4; ++i) {
        TEST_ASSERT_TRUE(limiter.recordFailure(i * kSecond));
        TEST_ASSERT_EQUAL_UINT32(0, limiter.retryAfterSeconds(i * kSecond));
        TEST_ASSERT_EQUAL_UINT32(i, limiter.failures());
    }
}

static void test_the_fifth_failure_waits_30_seconds() {
    RateLimiter limiter(kPolicy);
    for (int i = 0; i < 4; ++i) {
        limiter.recordFailure(0);
    }
    const int64_t at = 10 * kSecond;
    TEST_ASSERT_TRUE(limiter.recordFailure(at));
    TEST_ASSERT_EQUAL_UINT32(30, limiter.retryAfterSeconds(at));
    TEST_ASSERT_EQUAL_UINT32(30, limiter.retryAfterSeconds(at + 1));
    TEST_ASSERT_EQUAL_UINT32(1, limiter.retryAfterSeconds(at + 29 * kSecond + 1));
    TEST_ASSERT_EQUAL_UINT32(1, limiter.retryAfterSeconds(at + 30 * kSecond - 1));
    TEST_ASSERT_EQUAL_UINT32(0, limiter.retryAfterSeconds(at + 30 * kSecond));
}

static void test_each_later_failure_doubles_the_wait_up_to_15_minutes() {
    RateLimiter limiter(kPolicy);
    int64_t now = failUntilBlocked(limiter, 0);
    const uint32_t expected[] = {30, 60, 120, 240, 480, 900, 900, 900};
    for (uint32_t wait : expected) {
        TEST_ASSERT_EQUAL_UINT32(wait, limiter.retryAfterSeconds(now));
        now += wait * kSecond;
        TEST_ASSERT_EQUAL_UINT32(0, limiter.retryAfterSeconds(now));
        limiter.recordFailure(now);
    }
}

static void test_the_count_stops_changing_once_the_wait_is_capped() {
    RateLimiter limiter(kPolicy);
    int64_t now = 0;
    for (uint32_t i = 1; i <= 10; ++i) {
        now += 900 * kSecond;
        TEST_ASSERT_TRUE(limiter.recordFailure(now));
    }
    TEST_ASSERT_EQUAL_UINT32(10, limiter.failures());
    for (int i = 0; i < 3; ++i) {
        now += 900 * kSecond;
        TEST_ASSERT_FALSE(limiter.recordFailure(now));
        TEST_ASSERT_EQUAL_UINT32(10, limiter.failures());
        TEST_ASSERT_EQUAL_UINT32(900, limiter.retryAfterSeconds(now));
    }
}

static void test_a_success_resets_the_count() {
    RateLimiter limiter(kPolicy);
    int64_t now = failUntilBlocked(limiter, 0);
    now += 30 * kSecond;
    TEST_ASSERT_TRUE(limiter.recordSuccess());
    TEST_ASSERT_EQUAL_UINT32(0, limiter.failures());
    TEST_ASSERT_EQUAL_UINT32(0, limiter.retryAfterSeconds(now));
    TEST_ASSERT_TRUE(limiter.recordFailure(now));
    TEST_ASSERT_EQUAL_UINT32(1, limiter.failures());
    TEST_ASSERT_EQUAL_UINT32(0, limiter.retryAfterSeconds(now));
}

static void test_a_success_without_failures_changes_nothing() {
    RateLimiter limiter(kPolicy);
    TEST_ASSERT_FALSE(limiter.recordSuccess());
    TEST_ASSERT_EQUAL_UINT32(0, limiter.failures());
}

static void test_a_restored_count_below_the_threshold_does_not_wait() {
    RateLimiter limiter(kPolicy);
    limiter.restore(4, 1000 * kSecond);
    TEST_ASSERT_EQUAL_UINT32(4, limiter.failures());
    TEST_ASSERT_EQUAL_UINT32(0, limiter.retryAfterSeconds(1000 * kSecond));
    limiter.recordFailure(1000 * kSecond);
    TEST_ASSERT_EQUAL_UINT32(30, limiter.retryAfterSeconds(1000 * kSecond));
}

static void test_a_restored_count_waits_in_full_from_the_restore() {
    RateLimiter limiter(kPolicy);
    limiter.restore(7, 5 * kSecond);
    TEST_ASSERT_EQUAL_UINT32(120, limiter.retryAfterSeconds(5 * kSecond));
    TEST_ASSERT_EQUAL_UINT32(0, limiter.retryAfterSeconds(125 * kSecond));
    limiter.recordFailure(125 * kSecond);
    TEST_ASSERT_EQUAL_UINT32(240, limiter.retryAfterSeconds(125 * kSecond));
}

static void test_a_restored_count_is_capped() {
    RateLimiter limiter(kPolicy);
    limiter.restore(4000000000u, 0);
    TEST_ASSERT_EQUAL_UINT32(10, limiter.failures());
    TEST_ASSERT_EQUAL_UINT32(900, limiter.retryAfterSeconds(0));
    TEST_ASSERT_FALSE(limiter.recordFailure(900 * kSecond));
}

static void test_restoring_zero_clears_a_wait() {
    RateLimiter limiter(kPolicy);
    failUntilBlocked(limiter, 0);
    limiter.restore(0, 0);
    TEST_ASSERT_EQUAL_UINT32(0, limiter.failures());
    TEST_ASSERT_EQUAL_UINT32(0, limiter.retryAfterSeconds(0));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_four_failures_cost_nothing);
    RUN_TEST(test_the_fifth_failure_waits_30_seconds);
    RUN_TEST(test_each_later_failure_doubles_the_wait_up_to_15_minutes);
    RUN_TEST(test_the_count_stops_changing_once_the_wait_is_capped);
    RUN_TEST(test_a_success_resets_the_count);
    RUN_TEST(test_a_success_without_failures_changes_nothing);
    RUN_TEST(test_a_restored_count_below_the_threshold_does_not_wait);
    RUN_TEST(test_a_restored_count_waits_in_full_from_the_restore);
    RUN_TEST(test_a_restored_count_is_capped);
    RUN_TEST(test_restoring_zero_clears_a_wait);
    return UNITY_END();
}
