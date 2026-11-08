// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>

#include "latchkey_util/watch_schedule.h"

using latchkey_util::WatchSchedule;

void setUp() {}

void tearDown() {}

static constexpr int64_t kMinute = 60 * 1000;
static constexpr int64_t kInterval = 375 * kMinute;
static constexpr int64_t kRetry = 15 * kMinute;
static constexpr int64_t kGap = 2 * kMinute;
static constexpr int64_t kFirst = 1 * kMinute;
static constexpr int64_t kSpread = 5 * kMinute;
static constexpr int64_t kBoot = 10 * kMinute;

static WatchSchedule schedule(size_t index) {
    WatchSchedule watch(kInterval, kRetry, kGap);
    watch.begin(index, kBoot, kFirst, kSpread);
    return watch;
}

static void test_locks_are_first_watched_soon_after_boot_one_after_another() {
    const WatchSchedule first = schedule(0);
    const WatchSchedule third = schedule(2);
    TEST_ASSERT_FALSE(first.due(kBoot + kFirst - 1));
    TEST_ASSERT_TRUE(first.due(kBoot + kFirst));
    TEST_ASSERT_FALSE(third.due(kBoot + kFirst + 2 * kSpread - 1));
    TEST_ASSERT_TRUE(third.due(kBoot + kFirst + 2 * kSpread));
    TEST_ASSERT_EQUAL_INT64(kBoot + kFirst + 2 * kSpread, third.dueAtMs());
}

static void test_a_poll_waits_the_slow_interval_and_a_failure_the_retry() {
    WatchSchedule watch = schedule(0);
    const int64_t polled = kBoot + kFirst;
    watch.attempted(polled, true);
    TEST_ASSERT_FALSE(watch.due(polled + kInterval - 1));
    TEST_ASSERT_TRUE(watch.due(polled + kInterval));
    watch.attempted(polled + kInterval, false);
    TEST_ASSERT_FALSE(watch.due(polled + kInterval + kRetry - 1));
    TEST_ASSERT_TRUE(watch.due(polled + kInterval + kRetry));
}

static void test_a_link_opened_anyway_is_used_unless_a_poll_just_ran() {
    WatchSchedule watch = schedule(0);
    TEST_ASSERT_TRUE(watch.dueWithLink(kBoot));
    watch.attempted(kBoot, true);
    TEST_ASSERT_FALSE(watch.dueWithLink(kBoot + kGap - 1));
    TEST_ASSERT_TRUE(watch.dueWithLink(kBoot + kGap));
    watch.attempted(kBoot + kGap, true);
    TEST_ASSERT_FALSE(watch.due(kBoot + kGap + kInterval - 1));
}

static void test_a_latchkey_unlock_is_read_back_at_the_next_link() {
    WatchSchedule watch = schedule(0);
    watch.attempted(kBoot, true);
    watch.unlocked();
    TEST_ASSERT_TRUE(watch.dueWithLink(kBoot + 1));
    TEST_ASSERT_FALSE(watch.due(kBoot + 1));
    watch.attempted(kBoot + 1, true);
    TEST_ASSERT_FALSE(watch.dueWithLink(kBoot + 2));
}

static void test_a_failed_read_back_of_an_unlock_waits_for_the_retry() {
    WatchSchedule watch = schedule(0);
    watch.unlocked();
    watch.attempted(kBoot, false);
    TEST_ASSERT_FALSE(watch.dueWithLink(kBoot + kGap));
    TEST_ASSERT_TRUE(watch.due(kBoot + kRetry));
    TEST_ASSERT_TRUE(watch.dueWithLink(kBoot + kRetry));
}

static void test_a_poll_with_more_to_read_is_due_again_at_once() {
    WatchSchedule watch = schedule(0);
    watch.attempted(kBoot, true);
    watch.more();
    TEST_ASSERT_TRUE(watch.due(kBoot + 1));
    TEST_ASSERT_TRUE(watch.dueWithLink(kBoot + 1));
    watch.attempted(kBoot + 1, true);
    TEST_ASSERT_FALSE(watch.due(kBoot + 2));
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_locks_are_first_watched_soon_after_boot_one_after_another);
    RUN_TEST(test_a_poll_waits_the_slow_interval_and_a_failure_the_retry);
    RUN_TEST(test_a_link_opened_anyway_is_used_unless_a_poll_just_ran);
    RUN_TEST(test_a_latchkey_unlock_is_read_back_at_the_next_link);
    RUN_TEST(test_a_failed_read_back_of_an_unlock_waits_for_the_retry);
    RUN_TEST(test_a_poll_with_more_to_read_is_due_again_at_once);
    return UNITY_END();
}
