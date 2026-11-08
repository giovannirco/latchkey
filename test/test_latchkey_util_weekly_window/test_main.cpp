// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>
#include <string>
#include <vector>

#include "latchkey_util/weekly_window.h"
#include "ttlock/types.h"

using latchkey_util::WeeklyWindow;

void setUp() {}

void tearDown() {}

static void test_clock_times_are_two_digit_hours_and_minutes() {
    uint16_t minute = 0;
    TEST_ASSERT_TRUE(latchkey_util::parseClockTime("00:00", minute));
    TEST_ASSERT_EQUAL_UINT16(0, minute);
    TEST_ASSERT_TRUE(latchkey_util::parseClockTime("08:30", minute));
    TEST_ASSERT_EQUAL_UINT16(510, minute);
    TEST_ASSERT_TRUE(latchkey_util::parseClockTime("23:59", minute));
    TEST_ASSERT_EQUAL_UINT16(1439, minute);
    for (const char* text : {"24:00", "8:30", "08:3", "08:60", "08-30", "0830", "", "08:30 ", "+8:30", "ab:cd"}) {
        minute = 7;
        TEST_ASSERT_FALSE_MESSAGE(latchkey_util::parseClockTime(text, minute), text);
        TEST_ASSERT_EQUAL_UINT16(7, minute);
    }
}

static void test_clock_times_format_back_to_their_text() {
    TEST_ASSERT_EQUAL_STRING("00:00", latchkey_util::formatClockTime(0).c_str());
    TEST_ASSERT_EQUAL_STRING("08:30", latchkey_util::formatClockTime(510).c_str());
    TEST_ASSERT_EQUAL_STRING("23:59", latchkey_util::formatClockTime(1439).c_str());
    TEST_ASSERT_EQUAL_STRING("24:00", latchkey_util::formatClockTime(1440).c_str());
}

static void test_a_window_needs_a_day_and_must_run_forward_within_the_day() {
    TEST_ASSERT_TRUE(latchkey_util::isWeeklyWindow(WeeklyWindow{0x01, 0, 1}));
    TEST_ASSERT_TRUE(latchkey_util::isWeeklyWindow(WeeklyWindow{0x7F, 0, 1440}));
    TEST_ASSERT_FALSE(latchkey_util::isWeeklyWindow(WeeklyWindow{0x00, 0, 60}));
    TEST_ASSERT_FALSE(latchkey_util::isWeeklyWindow(WeeklyWindow{0x80, 0, 60}));
    TEST_ASSERT_FALSE(latchkey_util::isWeeklyWindow(WeeklyWindow{0x01, 60, 60}));
    TEST_ASSERT_FALSE(latchkey_util::isWeeklyWindow(WeeklyWindow{0x01, 90, 60}));
    TEST_ASSERT_FALSE(latchkey_util::isWeeklyWindow(WeeklyWindow{0x01, 0, 1441}));
}

static void test_weekdays_one_to_seven_are_monday_to_sunday() {
    uint8_t mask = 0;
    TEST_ASSERT_TRUE(latchkey_util::addWeekday(1, mask));
    TEST_ASSERT_TRUE(latchkey_util::addWeekday(7, mask));
    TEST_ASSERT_TRUE(latchkey_util::addWeekday(7, mask));
    TEST_ASSERT_EQUAL_UINT8(0x41, mask);
    TEST_ASSERT_FALSE(latchkey_util::addWeekday(0, mask));
    TEST_ASSERT_FALSE(latchkey_util::addWeekday(8, mask));
    TEST_ASSERT_EQUAL_UINT8(0x41, mask);
    const std::vector<uint8_t> days = latchkey_util::weekdays(0x55);
    const std::vector<uint8_t> expected{1, 3, 5, 7};
    TEST_ASSERT_EQUAL_UINT(expected.size(), days.size());
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected.data(), days.data(), expected.size());
}

static void test_a_window_becomes_one_lock_cycle_per_day() {
    const std::vector<ttlock::WeeklyCycle> cycles = latchkey_util::weeklyCycles(WeeklyWindow{0x15, 480, 1110});
    TEST_ASSERT_EQUAL_UINT(3, cycles.size());
    const uint8_t days[] = {1, 3, 5};
    for (size_t i = 0; i < cycles.size(); ++i) {
        TEST_ASSERT_EQUAL_UINT8(days[i], cycles[i].weekDay);
        TEST_ASSERT_EQUAL_UINT16(480, cycles[i].startMinuteOfDay);
        TEST_ASSERT_EQUAL_UINT16(1110, cycles[i].endMinuteOfDay);
    }
    TEST_ASSERT_EQUAL_UINT(0, latchkey_util::weeklyCycles(WeeklyWindow{0x00, 0, 60}).size());
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_clock_times_are_two_digit_hours_and_minutes);
    RUN_TEST(test_clock_times_format_back_to_their_text);
    RUN_TEST(test_a_window_needs_a_day_and_must_run_forward_within_the_day);
    RUN_TEST(test_weekdays_one_to_seven_are_monday_to_sunday);
    RUN_TEST(test_a_window_becomes_one_lock_cycle_per_day);
    return UNITY_END();
}
