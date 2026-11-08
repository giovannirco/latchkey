// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>

#include "latchkey_util/poll_schedule.h"

using latchkey_util::PollSchedule;

void setUp() {}

void tearDown() {}

static constexpr int64_t kInterval = 6 * 3600 * 1000LL;
static constexpr int64_t kRetry = 15 * 60 * 1000LL;
static constexpr int64_t kStart = 5000;

static void test_a_lock_never_polled_is_due_at_once() {
    const PollSchedule schedule(kInterval, kRetry);
    TEST_ASSERT_TRUE(schedule.due(0));
    TEST_ASSERT_TRUE(schedule.due(kStart));
}

static void test_an_answered_poll_waits_the_full_interval() {
    PollSchedule schedule(kInterval, kRetry);
    schedule.attempted(kStart, true);
    TEST_ASSERT_FALSE(schedule.due(kStart));
    TEST_ASSERT_FALSE(schedule.due(kStart + kInterval - 1));
    TEST_ASSERT_TRUE(schedule.due(kStart + kInterval));
}

static void test_an_unanswered_poll_retries_sooner() {
    PollSchedule schedule(kInterval, kRetry);
    schedule.attempted(kStart, false);
    TEST_ASSERT_FALSE(schedule.due(kStart + kRetry - 1));
    TEST_ASSERT_TRUE(schedule.due(kStart + kRetry));
    schedule.attempted(kStart + kRetry, true);
    TEST_ASSERT_FALSE(schedule.due(kStart + kRetry + kInterval - 1));
    TEST_ASSERT_TRUE(schedule.due(kStart + kRetry + kInterval));
}

static void test_a_fresh_reading_from_another_job_postpones_the_poll() {
    PollSchedule schedule(kInterval, kRetry);
    schedule.refreshed(kStart);
    TEST_ASSERT_FALSE(schedule.due(kStart + kInterval - 1));
    TEST_ASSERT_TRUE(schedule.due(kStart + kInterval));
    schedule.attempted(kStart + kInterval, false);
    schedule.refreshed(kStart + kInterval + 1000);
    TEST_ASSERT_FALSE(schedule.due(kStart + kInterval + kRetry));
    TEST_ASSERT_TRUE(schedule.due(kStart + 2 * kInterval + 1000));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_a_lock_never_polled_is_due_at_once);
    RUN_TEST(test_an_answered_poll_waits_the_full_interval);
    RUN_TEST(test_an_unanswered_poll_retries_sooner);
    RUN_TEST(test_a_fresh_reading_from_another_job_postpones_the_poll);
    return UNITY_END();
}
