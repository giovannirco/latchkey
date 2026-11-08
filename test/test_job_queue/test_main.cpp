// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>
#include <optional>
#include <vector>

#include "latchkey_util/job_queue.h"

using Queue = latchkey_util::JobQueue<int>;

void setUp() {}

void tearDown() {}

static constexpr uint32_t kLimit = Queue::kWaitLimitMs;

static void assertJobs(const std::vector<int>& expected, const std::vector<int>& actual) {
    TEST_ASSERT_EQUAL_UINT(expected.size(), actual.size());
    for (size_t i = 0; i < expected.size(); ++i) {
        TEST_ASSERT_EQUAL_INT(expected[i], actual[i]);
    }
}

static int popOrFail(Queue& queue, uint32_t nowMs) {
    const std::optional<int> job = queue.pop(nowMs);
    TEST_ASSERT_TRUE_MESSAGE(job.has_value(), "expected a job");
    return *job;
}

static void test_wait_limit_is_sixty_seconds() { TEST_ASSERT_EQUAL_UINT32(60000, kLimit); }

static void test_starts_empty() {
    Queue queue;
    TEST_ASSERT_TRUE(queue.empty());
    TEST_ASSERT_EQUAL_UINT(0, queue.size());
    TEST_ASSERT_FALSE(queue.pop(0).has_value());
    TEST_ASSERT_TRUE(queue.expire(kLimit * 10).empty());
}

static void test_jobs_run_in_submission_order() {
    Queue queue;
    TEST_ASSERT_TRUE(queue.push(1, 0));
    TEST_ASSERT_TRUE(queue.push(2, 5));
    TEST_ASSERT_TRUE(queue.push(3, 5));
    TEST_ASSERT_EQUAL_UINT(3, queue.size());
    TEST_ASSERT_EQUAL_INT(1, popOrFail(queue, 10));
    TEST_ASSERT_EQUAL_INT(2, popOrFail(queue, 10));
    TEST_ASSERT_TRUE(queue.push(4, 11));
    TEST_ASSERT_EQUAL_INT(3, popOrFail(queue, 12));
    TEST_ASSERT_EQUAL_INT(4, popOrFail(queue, 12));
    TEST_ASSERT_TRUE(queue.empty());
}

static void test_a_full_queue_refuses_until_a_job_leaves() {
    Queue queue(2);
    TEST_ASSERT_TRUE(queue.push(1, 0));
    TEST_ASSERT_TRUE(queue.push(2, 0));
    TEST_ASSERT_FALSE(queue.push(3, 0));
    TEST_ASSERT_EQUAL_UINT(2, queue.size());
    TEST_ASSERT_EQUAL_INT(1, popOrFail(queue, 1));
    TEST_ASSERT_TRUE(queue.push(3, 1));
    TEST_ASSERT_EQUAL_INT(2, popOrFail(queue, 1));
    TEST_ASSERT_EQUAL_INT(3, popOrFail(queue, 1));
}

static void test_default_capacity_is_eight() {
    Queue queue;
    for (int job = 0; job < 8; ++job) {
        TEST_ASSERT_TRUE(queue.push(job, 0));
    }
    TEST_ASSERT_FALSE(queue.push(8, 0));
}

static void test_a_job_that_waited_exactly_the_limit_still_runs() {
    Queue queue;
    TEST_ASSERT_TRUE(queue.push(7, 1000));
    TEST_ASSERT_TRUE(queue.expire(1000 + kLimit).empty());
    TEST_ASSERT_EQUAL_INT(7, popOrFail(queue, 1000 + kLimit));
}

static void test_one_millisecond_past_the_limit_expires() {
    Queue queue;
    TEST_ASSERT_TRUE(queue.push(7, 1000));
    assertJobs({7}, queue.expire(1000 + kLimit + 1));
    TEST_ASSERT_TRUE(queue.empty());
    TEST_ASSERT_TRUE(queue.expire(1000 + 2 * kLimit).empty());
}

static void test_expire_takes_only_old_jobs_and_keeps_the_order_of_the_rest() {
    Queue queue;
    TEST_ASSERT_TRUE(queue.push(1, 0));
    TEST_ASSERT_TRUE(queue.push(2, 100));
    TEST_ASSERT_TRUE(queue.push(3, 30000));
    TEST_ASSERT_TRUE(queue.push(4, 50000));
    assertJobs({1, 2}, queue.expire(kLimit + 101));
    TEST_ASSERT_EQUAL_UINT(2, queue.size());
    TEST_ASSERT_EQUAL_INT(3, popOrFail(queue, kLimit + 101));
    TEST_ASSERT_EQUAL_INT(4, popOrFail(queue, kLimit + 101));
}

static void test_pop_never_hands_out_a_job_past_the_limit() {
    Queue queue;
    TEST_ASSERT_TRUE(queue.push(1, 0));
    TEST_ASSERT_TRUE(queue.push(2, 20000));
    TEST_ASSERT_EQUAL_INT(2, popOrFail(queue, kLimit + 1));
    TEST_ASSERT_FALSE(queue.pop(kLimit + 1).has_value());
    assertJobs({1}, queue.expire(kLimit + 1));
    TEST_ASSERT_TRUE(queue.empty());
}

static void test_waits_are_measured_across_the_millisecond_counter_wrap() {
    Queue queue;
    const uint32_t enqueued = UINT32_MAX - 499;
    TEST_ASSERT_TRUE(queue.push(1, enqueued));
    TEST_ASSERT_TRUE(queue.expire(UINT32_MAX - 100).empty());
    TEST_ASSERT_TRUE(queue.expire(1000).empty());
    TEST_ASSERT_EQUAL_UINT(1, queue.size());
    assertJobs({1}, queue.expire(enqueued + kLimit + 1));
}

static void test_a_long_job_makes_later_waiters_busy_in_order() {
    Queue queue;
    TEST_ASSERT_TRUE(queue.push(1, 0));
    TEST_ASSERT_TRUE(queue.push(2, 1000));
    TEST_ASSERT_EQUAL_INT(1, popOrFail(queue, 1000));
    TEST_ASSERT_TRUE(queue.push(3, 61000));
    TEST_ASSERT_TRUE(queue.expire(61000).empty());
    assertJobs({2}, queue.expire(61001));
    TEST_ASSERT_TRUE(queue.expire(121000).empty());
    TEST_ASSERT_EQUAL_INT(3, popOrFail(queue, 121000));
    TEST_ASSERT_TRUE(queue.empty());
}

static void test_moves_jobs_it_cannot_copy() {
    latchkey_util::JobQueue<std::vector<int>> queue;
    TEST_ASSERT_TRUE(queue.push(std::vector<int>{1, 2, 3}, 0));
    const std::optional<std::vector<int>> job = queue.pop(0);
    TEST_ASSERT_TRUE(job.has_value());
    assertJobs({1, 2, 3}, *job);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_wait_limit_is_sixty_seconds);
    RUN_TEST(test_starts_empty);
    RUN_TEST(test_jobs_run_in_submission_order);
    RUN_TEST(test_a_full_queue_refuses_until_a_job_leaves);
    RUN_TEST(test_default_capacity_is_eight);
    RUN_TEST(test_a_job_that_waited_exactly_the_limit_still_runs);
    RUN_TEST(test_one_millisecond_past_the_limit_expires);
    RUN_TEST(test_expire_takes_only_old_jobs_and_keeps_the_order_of_the_rest);
    RUN_TEST(test_pop_never_hands_out_a_job_past_the_limit);
    RUN_TEST(test_waits_are_measured_across_the_millisecond_counter_wrap);
    RUN_TEST(test_a_long_job_makes_later_waiters_busy_in_order);
    RUN_TEST(test_moves_jobs_it_cannot_copy);
    return UNITY_END();
}
