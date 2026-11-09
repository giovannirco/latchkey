// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <string>
#include <vector>

#include "latchkey_util/lock_settings.h"
#include "ttlock/types.h"

using ttlock::AutoLockSetting;
using ttlock::PassageMode;
using ttlock::PassageType;

void setUp() {}

void tearDown() {}

static PassageMode untouched() {
    return PassageMode{PassageType::Monthly, 9, 9, 9, 9, 9, 9};
}

static void assertUntouched(const PassageMode& mode) { TEST_ASSERT_TRUE(mode == untouched()); }

static void test_weekly_passage_days_run_from_every_day_to_sunday() {
    PassageMode mode = untouched();
    TEST_ASSERT_TRUE(latchkey_util::makePassage(PassageType::Weekly, 0, "08:05", "18:40", mode));
    TEST_ASSERT_TRUE(mode == (PassageMode{PassageType::Weekly, 0, 0, 8, 5, 18, 40}));
    TEST_ASSERT_TRUE(latchkey_util::makePassage(PassageType::Weekly, 7, "00:00", "23:59", mode));
    TEST_ASSERT_TRUE(mode == (PassageMode{PassageType::Weekly, 7, 0, 0, 0, 23, 59}));
    for (int day : {-1, 8, 31}) {
        mode = untouched();
        TEST_ASSERT_FALSE(latchkey_util::makePassage(PassageType::Weekly, day, "08:00", "09:00", mode));
        assertUntouched(mode);
    }
}

static void test_monthly_passage_days_are_days_of_the_month() {
    PassageMode mode = untouched();
    TEST_ASSERT_TRUE(latchkey_util::makePassage(PassageType::Monthly, 1, "06:00", "07:00", mode));
    TEST_ASSERT_TRUE(mode == (PassageMode{PassageType::Monthly, 1, 0, 6, 0, 7, 0}));
    TEST_ASSERT_TRUE(latchkey_util::makePassage(PassageType::Monthly, 31, "06:00", "07:00", mode));
    for (int day : {0, 32}) {
        mode = untouched();
        TEST_ASSERT_FALSE(latchkey_util::makePassage(PassageType::Monthly, day, "06:00", "07:00", mode));
        assertUntouched(mode);
    }
}

static void test_passage_times_are_clock_times() {
    for (const char* text : {"24:00", "8:00", "08:60", "", "08:00 "}) {
        PassageMode mode = untouched();
        TEST_ASSERT_FALSE_MESSAGE(latchkey_util::makePassage(PassageType::Weekly, 1, text, "23:00", mode), text);
        TEST_ASSERT_FALSE_MESSAGE(latchkey_util::makePassage(PassageType::Weekly, 1, "01:00", text, mode), text);
        assertUntouched(mode);
    }
}

static void test_a_passage_window_must_run_forward_to_be_added() {
    PassageMode mode;
    TEST_ASSERT_TRUE(latchkey_util::makePassage(PassageType::Weekly, 1, "08:00", "08:01", mode));
    TEST_ASSERT_TRUE(latchkey_util::runsForward(mode));
    TEST_ASSERT_TRUE(latchkey_util::makePassage(PassageType::Weekly, 1, "08:00", "08:00", mode));
    TEST_ASSERT_FALSE(latchkey_util::runsForward(mode));
    TEST_ASSERT_TRUE(latchkey_util::makePassage(PassageType::Weekly, 1, "22:00", "06:00", mode));
    TEST_ASSERT_FALSE(latchkey_util::runsForward(mode));
}

static void test_passage_types_have_the_names_the_api_uses() {
    PassageType type = PassageType::Monthly;
    TEST_ASSERT_TRUE(latchkey_util::passageTypeOf("weekly", type));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(PassageType::Weekly), static_cast<int>(type));
    TEST_ASSERT_TRUE(latchkey_util::passageTypeOf("monthly", type));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(PassageType::Monthly), static_cast<int>(type));
    for (const char* name : {"daily", "Weekly", "", "weekly "}) {
        type = PassageType::Weekly;
        TEST_ASSERT_FALSE_MESSAGE(latchkey_util::passageTypeOf(name, type), name);
        TEST_ASSERT_EQUAL_INT(static_cast<int>(PassageType::Weekly), static_cast<int>(type));
    }
    TEST_ASSERT_EQUAL_STRING("weekly", latchkey_util::passageTypeName(PassageType::Weekly));
    TEST_ASSERT_EQUAL_STRING("monthly", latchkey_util::passageTypeName(PassageType::Monthly));
}

static void test_passage_lists_render_as_the_api_writes_them() {
    const std::vector<PassageMode> modes{
        PassageMode{PassageType::Weekly, 0, 0, 8, 0, 9, 0},
        PassageMode{PassageType::Weekly, 1, 0, 18, 30, 23, 59},
        PassageMode{PassageType::Monthly, 15, 3, 0, 0, 6, 5},
    };
    TEST_ASSERT_EQUAL_STRING(
        R"([{"type":"weekly","day":0,"start":"08:00","end":"09:00"},)"
        R"({"type":"weekly","day":1,"start":"18:30","end":"23:59"},)"
        R"({"type":"monthly","day":15,"month":3,"start":"00:00","end":"06:05"}])",
        latchkey_util::passageListJson(modes).c_str());
    TEST_ASSERT_EQUAL_STRING("[]", latchkey_util::passageListJson({}).c_str());
}

static void test_a_listed_mode_with_impossible_fields_is_still_rendered() {
    const std::vector<PassageMode> modes{PassageMode{static_cast<PassageType>(9), 40, 0, 25, 61, 0, 0}};
    TEST_ASSERT_EQUAL_STRING(R"([{"type":"other","day":40,"start":"25:61","end":"00:00"}])",
                             latchkey_util::passageListJson(modes).c_str());
}

static void test_auto_lock_is_off_or_a_delay_within_the_lock_range() {
    const AutoLockSetting range{5, 1, 900};
    TEST_ASSERT_TRUE(latchkey_util::autolockAllowed(0, range));
    TEST_ASSERT_TRUE(latchkey_util::autolockAllowed(1, range));
    TEST_ASSERT_TRUE(latchkey_util::autolockAllowed(900, range));
    TEST_ASSERT_FALSE(latchkey_util::autolockAllowed(901, range));
    const AutoLockSetting narrow{0, 5, 120};
    TEST_ASSERT_FALSE(latchkey_util::autolockAllowed(4, narrow));
    TEST_ASSERT_TRUE(latchkey_util::autolockAllowed(5, narrow));
    TEST_ASSERT_FALSE(latchkey_util::autolockAllowed(121, narrow));
}

static void test_a_lock_that_reports_no_range_takes_any_delay_it_can_store() {
    const AutoLockSetting unreported{10, 0, 0};
    TEST_ASSERT_TRUE(latchkey_util::autolockAllowed(0, unreported));
    TEST_ASSERT_TRUE(latchkey_util::autolockAllowed(65535, unreported));
    TEST_ASSERT_FALSE(latchkey_util::autolockAllowed(65536, unreported));
}

static void test_auto_lock_renders_its_range_or_null() {
    TEST_ASSERT_EQUAL_STRING(R"({"seconds":5,"min":1,"max":900})",
                             latchkey_util::autolockJson(AutoLockSetting{5, 1, 900}).c_str());
    TEST_ASSERT_EQUAL_STRING(R"({"seconds":0,"min":null,"max":null})",
                             latchkey_util::autolockJson(AutoLockSetting{0, 0, 0}).c_str());
}

static void test_a_passage_add_that_stops_part_way_says_how_many_windows_were_added() {
    TEST_ASSERT_EQUAL_STRING("the lock did not answer; 1 passage window was added before that",
                             latchkey_util::passageAddStopped("the lock did not answer", 1).c_str());
    TEST_ASSERT_EQUAL_STRING("the lock did not answer; 3 passage windows were added before that",
                             latchkey_util::passageAddStopped("the lock did not answer", 3).c_str());
}

static void test_a_passage_add_that_stops_before_any_window_keeps_the_failure() {
    TEST_ASSERT_EQUAL_STRING("the lock did not answer",
                             latchkey_util::passageAddStopped("the lock did not answer", 0).c_str());
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_weekly_passage_days_run_from_every_day_to_sunday);
    RUN_TEST(test_monthly_passage_days_are_days_of_the_month);
    RUN_TEST(test_passage_times_are_clock_times);
    RUN_TEST(test_a_passage_window_must_run_forward_to_be_added);
    RUN_TEST(test_passage_types_have_the_names_the_api_uses);
    RUN_TEST(test_passage_lists_render_as_the_api_writes_them);
    RUN_TEST(test_a_listed_mode_with_impossible_fields_is_still_rendered);
    RUN_TEST(test_auto_lock_is_off_or_a_delay_within_the_lock_range);
    RUN_TEST(test_a_lock_that_reports_no_range_takes_any_delay_it_can_store);
    RUN_TEST(test_auto_lock_renders_its_range_or_null);
    RUN_TEST(test_a_passage_add_that_stops_part_way_says_how_many_windows_were_added);
    RUN_TEST(test_a_passage_add_that_stops_before_any_window_keeps_the_failure);
    return UNITY_END();
}
