// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>

#include "latchkey_util/repeat_filter.h"

using latchkey_util::RepeatFilter;

void setUp() {}

void tearDown() {}

static constexpr uint32_t kWindow = 2000;

static void test_nothing_repeats_before_a_note() {
    const RepeatFilter filter(kWindow);
    TEST_ASSERT_FALSE(filter.repeats("unlock", 0));
    TEST_ASSERT_FALSE(filter.repeats("", 0));
}

static void test_the_same_key_repeats_within_the_window() {
    RepeatFilter filter(kWindow);
    filter.note("unlock", 1000);
    TEST_ASSERT_TRUE(filter.repeats("unlock", 1000));
    TEST_ASSERT_TRUE(filter.repeats("unlock", 2500));
    TEST_ASSERT_TRUE(filter.repeats("unlock", 1000 + kWindow));
    TEST_ASSERT_FALSE(filter.repeats("unlock", 1000 + kWindow + 1));
}

static void test_another_key_does_not_repeat() {
    RepeatFilter filter(kWindow);
    filter.note("unlock", 1000);
    TEST_ASSERT_FALSE(filter.repeats("lock", 1100));
    TEST_ASSERT_FALSE(filter.repeats("unlock-later", 1100));
}

static void test_a_newer_note_replaces_the_older_one() {
    RepeatFilter filter(kWindow);
    filter.note("unlock", 0);
    filter.note("lock", 500);
    TEST_ASSERT_FALSE(filter.repeats("unlock", 600));
    TEST_ASSERT_TRUE(filter.repeats("lock", 600));
    filter.note("lock", 2400);
    TEST_ASSERT_TRUE(filter.repeats("lock", 4400));
}

static void test_asking_does_not_extend_the_window() {
    RepeatFilter filter(kWindow);
    filter.note("unlock", 0);
    TEST_ASSERT_TRUE(filter.repeats("unlock", 1900));
    TEST_ASSERT_FALSE(filter.repeats("unlock", 2100));
}

static void test_the_window_holds_across_the_millisecond_counter_wrap() {
    RepeatFilter filter(kWindow);
    const uint32_t noted = UINT32_MAX - 499;
    filter.note("unlock", noted);
    TEST_ASSERT_TRUE(filter.repeats("unlock", UINT32_MAX - 100));
    TEST_ASSERT_TRUE(filter.repeats("unlock", 1000));
    TEST_ASSERT_FALSE(filter.repeats("unlock", noted + kWindow + 1));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_nothing_repeats_before_a_note);
    RUN_TEST(test_the_same_key_repeats_within_the_window);
    RUN_TEST(test_another_key_does_not_repeat);
    RUN_TEST(test_a_newer_note_replaces_the_older_one);
    RUN_TEST(test_asking_does_not_extend_the_window);
    RUN_TEST(test_the_window_holds_across_the_millisecond_counter_wrap);
    return UNITY_END();
}
