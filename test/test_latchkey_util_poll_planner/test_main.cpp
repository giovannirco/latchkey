// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>
#include <optional>
#include <string>

#include "latchkey_util/poll_planner.h"

using latchkey_util::PollPlanner;

void setUp() {}

void tearDown() {}

static constexpr int64_t kInterval = 6 * 3600 * 1000LL;
static constexpr int64_t kRetry = 15 * 60 * 1000LL;
static constexpr int64_t kGap = 60 * 1000LL;

static void assertNext(const PollPlanner& planner, int64_t now, bool idle, const char* lock) {
    const std::optional<std::string> next = planner.next(now, idle);
    TEST_ASSERT_TRUE_MESSAGE(next.has_value(), lock);
    TEST_ASSERT_EQUAL_STRING(lock, next->c_str());
}

static void test_only_one_lock_is_polled_at_a_time() {
    PollPlanner planner(kInterval, kRetry, kGap);
    planner.track("aaaaaaaaaaaa");
    planner.track("bbbbbbbbbbbb");
    assertNext(planner, 0, true, "aaaaaaaaaaaa");
    planner.started("aaaaaaaaaaaa");
    TEST_ASSERT_FALSE(planner.next(0, true).has_value());
    TEST_ASSERT_FALSE(planner.next(30 * 1000, true).has_value());
    planner.finished("aaaaaaaaaaaa", 40 * 1000, true);
    TEST_ASSERT_FALSE(planner.next(40 * 1000 + kGap - 1, true).has_value());
    assertNext(planner, 40 * 1000 + kGap, true, "bbbbbbbbbbbb");
}

static void test_a_poll_waits_for_an_idle_job_queue() {
    PollPlanner planner(kInterval, kRetry, kGap);
    planner.track("aaaaaaaaaaaa");
    TEST_ASSERT_FALSE(planner.next(0, false).has_value());
    assertNext(planner, 0, true, "aaaaaaaaaaaa");
}

static void test_the_next_polls_are_spread_by_their_finish_times() {
    PollPlanner planner(kInterval, kRetry, kGap);
    planner.track("aaaaaaaaaaaa");
    planner.track("bbbbbbbbbbbb");
    planner.started("aaaaaaaaaaaa");
    planner.finished("aaaaaaaaaaaa", 10 * 1000, true);
    const int64_t second = 10 * 1000 + kGap;
    assertNext(planner, second, true, "bbbbbbbbbbbb");
    planner.started("bbbbbbbbbbbb");
    planner.finished("bbbbbbbbbbbb", second + 20 * 1000, true);
    TEST_ASSERT_FALSE(planner.next(10 * 1000 + kInterval - 1, true).has_value());
    assertNext(planner, 10 * 1000 + kInterval, true, "aaaaaaaaaaaa");
    planner.started("aaaaaaaaaaaa");
    planner.finished("aaaaaaaaaaaa", 10 * 1000 + kInterval + 5 * 1000, true);
    TEST_ASSERT_FALSE(planner.next(second + 20 * 1000 + kInterval - 1, true).has_value());
    assertNext(planner, second + 20 * 1000 + kInterval, true, "bbbbbbbbbbbb");
}

static void test_an_unanswered_poll_is_retried_sooner_and_a_fresh_reading_postpones() {
    PollPlanner planner(kInterval, kRetry, kGap);
    planner.track("aaaaaaaaaaaa");
    planner.started("aaaaaaaaaaaa");
    planner.finished("aaaaaaaaaaaa", 0, false);
    TEST_ASSERT_FALSE(planner.next(kRetry - 1, true).has_value());
    assertNext(planner, kRetry, true, "aaaaaaaaaaaa");
    planner.refreshed("aaaaaaaaaaaa", kRetry);
    TEST_ASSERT_FALSE(planner.next(kRetry + kInterval - 1, true).has_value());
    assertNext(planner, kRetry + kInterval, true, "aaaaaaaaaaaa");
}

static void test_a_forgotten_lock_is_not_polled_but_its_running_poll_still_blocks() {
    PollPlanner planner(kInterval, kRetry, kGap);
    planner.track("aaaaaaaaaaaa");
    planner.track("bbbbbbbbbbbb");
    planner.started("aaaaaaaaaaaa");
    planner.forget("aaaaaaaaaaaa");
    TEST_ASSERT_FALSE(planner.next(0, true).has_value());
    planner.finished("aaaaaaaaaaaa", 1000, true);
    assertNext(planner, 1000 + kGap, true, "bbbbbbbbbbbb");
    planner.forget("bbbbbbbbbbbb");
    TEST_ASSERT_FALSE(planner.next(1000 + 2 * kGap, true).has_value());
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_only_one_lock_is_polled_at_a_time);
    RUN_TEST(test_a_poll_waits_for_an_idle_job_queue);
    RUN_TEST(test_the_next_polls_are_spread_by_their_finish_times);
    RUN_TEST(test_an_unanswered_poll_is_retried_sooner_and_a_fresh_reading_postpones);
    RUN_TEST(test_a_forgotten_lock_is_not_polled_but_its_running_poll_still_blocks);
    return UNITY_END();
}
