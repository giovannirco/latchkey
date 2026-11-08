// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>

#include "latchkey_util/connection_backoff.h"

using latchkey_util::ConnectionBackoff;

void setUp() {}

void tearDown() {}

static constexpr int64_t kSecond = 1000;
static constexpr int64_t kStable = 60 * kSecond;

static ConnectionBackoff backoff() { return ConnectionBackoff({1, 1, 120}, kStable); }

static void test_failed_attempts_double_the_wait_up_to_two_minutes() {
    ConnectionBackoff waits = backoff();
    TEST_ASSERT_EQUAL_UINT32(0, waits.retryAfterSeconds(0));
    int64_t now = 0;
    const uint32_t expected[] = {1, 2, 4, 8, 16, 32, 64, 120, 120};
    for (uint32_t wait : expected) {
        waits.disconnected(now);
        TEST_ASSERT_EQUAL_UINT32(wait, waits.retryAfterSeconds(now));
        now += wait * kSecond;
        TEST_ASSERT_EQUAL_UINT32(0, waits.retryAfterSeconds(now));
    }
}

static void test_a_connection_dropped_soon_after_it_was_accepted_keeps_doubling() {
    ConnectionBackoff waits = backoff();
    waits.disconnected(0);
    waits.connected(1 * kSecond);
    waits.disconnected(6 * kSecond);
    TEST_ASSERT_EQUAL_UINT32(2, waits.retryAfterSeconds(6 * kSecond));
    waits.connected(8 * kSecond);
    waits.disconnected(8 * kSecond + kStable - 1);
    TEST_ASSERT_EQUAL_UINT32(4, waits.retryAfterSeconds(8 * kSecond + kStable - 1));
}

static void test_a_connection_that_held_starts_the_waits_again() {
    ConnectionBackoff waits = backoff();
    for (int i = 0; i < 5; ++i) {
        waits.disconnected(0);
    }
    waits.connected(100 * kSecond);
    waits.disconnected(100 * kSecond + kStable);
    TEST_ASSERT_EQUAL_UINT32(1, waits.retryAfterSeconds(100 * kSecond + kStable));
}

static void test_new_settings_clear_the_wait() {
    ConnectionBackoff waits = backoff();
    for (int i = 0; i < 4; ++i) {
        waits.disconnected(0);
    }
    TEST_ASSERT_EQUAL_UINT32(8, waits.retryAfterSeconds(0));
    waits.reset();
    TEST_ASSERT_EQUAL_UINT32(0, waits.retryAfterSeconds(0));
    waits.disconnected(0);
    TEST_ASSERT_EQUAL_UINT32(1, waits.retryAfterSeconds(0));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_failed_attempts_double_the_wait_up_to_two_minutes);
    RUN_TEST(test_a_connection_dropped_soon_after_it_was_accepted_keeps_doubling);
    RUN_TEST(test_a_connection_that_held_starts_the_waits_again);
    RUN_TEST(test_new_settings_clear_the_wait);
    return UNITY_END();
}
