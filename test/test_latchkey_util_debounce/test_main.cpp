// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include "latchkey_util/debounce.h"

void setUp() {}

void tearDown() {}

static int pressesFor(latchkey_util::Debouncer& debouncer, const char* samples) {
    int presses = 0;
    for (const char* sample = samples; *sample != '\0'; ++sample) {
        if (debouncer.update(*sample == '1')) {
            ++presses;
        }
    }
    return presses;
}

static void test_starts_released() {
    latchkey_util::Debouncer debouncer(3);
    TEST_ASSERT_FALSE(debouncer.pressed());
}

static void test_press_needs_stable_samples_and_fires_once() {
    latchkey_util::Debouncer debouncer(3);
    TEST_ASSERT_EQUAL_INT(0, pressesFor(debouncer, "11"));
    TEST_ASSERT_FALSE(debouncer.pressed());
    TEST_ASSERT_EQUAL_INT(1, pressesFor(debouncer, "1"));
    TEST_ASSERT_TRUE(debouncer.pressed());
    TEST_ASSERT_EQUAL_INT(0, pressesFor(debouncer, "1111111111"));
    TEST_ASSERT_TRUE(debouncer.pressed());
}

static void test_bounces_do_not_press() {
    latchkey_util::Debouncer debouncer(3);
    TEST_ASSERT_EQUAL_INT(0, pressesFor(debouncer, "1010110110010"));
    TEST_ASSERT_FALSE(debouncer.pressed());
}

static void test_release_needs_stable_samples_before_the_next_press() {
    latchkey_util::Debouncer debouncer(3);
    TEST_ASSERT_EQUAL_INT(1, pressesFor(debouncer, "111"));
    TEST_ASSERT_EQUAL_INT(0, pressesFor(debouncer, "0010011"));
    TEST_ASSERT_TRUE(debouncer.pressed());
    TEST_ASSERT_EQUAL_INT(0, pressesFor(debouncer, "000"));
    TEST_ASSERT_FALSE(debouncer.pressed());
    TEST_ASSERT_EQUAL_INT(1, pressesFor(debouncer, "0111"));
}

static void test_two_separate_presses_count_twice() {
    latchkey_util::Debouncer debouncer(2);
    TEST_ASSERT_EQUAL_INT(2, pressesFor(debouncer, "1100011100"));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_starts_released);
    RUN_TEST(test_press_needs_stable_samples_and_fires_once);
    RUN_TEST(test_bounces_do_not_press);
    RUN_TEST(test_release_needs_stable_samples_before_the_next_press);
    RUN_TEST(test_two_separate_presses_count_twice);
    return UNITY_END();
}
