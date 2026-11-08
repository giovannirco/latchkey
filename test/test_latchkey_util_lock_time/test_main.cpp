// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>

#include "latchkey_util/lock_time.h"
#include "latchkey_util/tz.h"
#include "ttlock/types.h"

using latchkey_util::UtcOffsetAt;
using ttlock::LockTime;
using ttlock::Validity;

void setUp() {}

void tearDown() {}

static constexpr int64_t k2026Nov8Noon = 1794139200;
static constexpr int64_t k2026Jul1TenUtc = 1782900000;
static constexpr int64_t k2026Jan15ElevenUtc = 1768474800;
static constexpr int64_t k2026Mar28TwentyTwoUtc = 1774735200;
static constexpr int64_t k2026Mar29TwentyTwoUtc = 1774821600;
static constexpr int64_t k2000 = 946684800;
static constexpr int64_t k2099LastMinute = 4102444740;
static constexpr int64_t k2100 = 4102444800;

static UtcOffsetAt fixed(int32_t offset) {
    return [offset](int64_t) { return offset; };
}

static UtcOffsetAt zone(const char* text) {
    latchkey_util::TimeZone parsed;
    TEST_ASSERT_TRUE(latchkey_util::parseTimeZone(text, parsed));
    return [parsed](int64_t utc) { return latchkey_util::utcOffsetAt(parsed, utc); };
}

static void assertTime(const LockTime& expected, const LockTime& actual) {
    TEST_ASSERT_EQUAL_UINT16(expected.year, actual.year);
    TEST_ASSERT_EQUAL_UINT8(expected.month, actual.month);
    TEST_ASSERT_EQUAL_UINT8(expected.day, actual.day);
    TEST_ASSERT_EQUAL_UINT8(expected.hour, actual.hour);
    TEST_ASSERT_EQUAL_UINT8(expected.minute, actual.minute);
    TEST_ASSERT_EQUAL_UINT8(expected.second, actual.second);
}

static void test_a_lock_time_counts_seconds_like_a_utc_calendar() {
    int64_t seconds = 0;
    TEST_ASSERT_TRUE(latchkey_util::localSecondsOf(LockTime{2024, 2, 29, 12, 30, 0}, seconds));
    TEST_ASSERT_EQUAL_INT64(1709209800, seconds);
    TEST_ASSERT_TRUE(latchkey_util::localSecondsOf(LockTime{2000, 1, 1, 0, 0, 0}, seconds));
    TEST_ASSERT_EQUAL_INT64(k2000, seconds);
}

static void test_a_time_that_cannot_exist_has_no_seconds() {
    const LockTime impossible[] = {
        {2026, 0, 1, 0, 0, 0},  {2026, 13, 1, 0, 0, 0}, {2026, 11, 31, 0, 0, 0}, {2025, 2, 29, 0, 0, 0},
        {2026, 1, 0, 0, 0, 0},  {2026, 1, 1, 24, 0, 0}, {2026, 1, 1, 0, 60, 0},  {2026, 1, 1, 0, 0, 60},
    };
    for (const LockTime& time : impossible) {
        int64_t seconds = 42;
        TEST_ASSERT_FALSE(latchkey_util::localSecondsOf(time, seconds));
        TEST_ASSERT_EQUAL_INT64(42, seconds);
    }
}

static void test_the_lock_is_given_local_time_at_that_instant() {
    assertTime(LockTime{2026, 11, 8, 12, 0, 0}, latchkey_util::lockTimeAt(k2026Nov8Noon, fixed(0)));
    assertTime(LockTime{2026, 11, 8, 9, 0, 0}, latchkey_util::lockTimeAt(k2026Nov8Noon, fixed(-3 * 3600)));
    const UtcOffsetAt europe = zone("CET-1CEST,M3.5.0,M10.5.0/3");
    assertTime(LockTime{2026, 7, 1, 12, 0, 0}, latchkey_util::lockTimeAt(k2026Jul1TenUtc, europe));
    assertTime(LockTime{2026, 1, 15, 12, 0, 0}, latchkey_util::lockTimeAt(k2026Jan15ElevenUtc, europe));
}

static void test_a_lock_time_maps_back_to_utc_with_its_own_offset() {
    const UtcOffsetAt europe = zone("CET-1CEST,M3.5.0,M10.5.0/3");
    int64_t utc = 0;
    TEST_ASSERT_TRUE(latchkey_util::utcOfLockTime(LockTime{2026, 7, 1, 12, 0, 0}, europe, utc));
    TEST_ASSERT_EQUAL_INT64(k2026Jul1TenUtc, utc);
    TEST_ASSERT_TRUE(latchkey_util::utcOfLockTime(LockTime{2026, 1, 15, 12, 0, 0}, europe, utc));
    TEST_ASSERT_EQUAL_INT64(k2026Jan15ElevenUtc, utc);
    TEST_ASSERT_TRUE(latchkey_util::utcOfLockTime(LockTime{2026, 3, 28, 23, 0, 0}, europe, utc));
    TEST_ASSERT_EQUAL_INT64(k2026Mar28TwentyTwoUtc, utc);
    TEST_ASSERT_TRUE(latchkey_util::utcOfLockTime(LockTime{2026, 3, 30, 0, 0, 0}, europe, utc));
    TEST_ASSERT_EQUAL_INT64(k2026Mar29TwentyTwoUtc, utc);
    TEST_ASSERT_TRUE(latchkey_util::utcOfLockTime(LockTime{2026, 11, 8, 9, 0, 0}, fixed(-3 * 3600), utc));
    TEST_ASSERT_EQUAL_INT64(k2026Nov8Noon, utc);
    utc = 7;
    TEST_ASSERT_FALSE(latchkey_util::utcOfLockTime(LockTime{2026, 2, 30, 0, 0, 0}, europe, utc));
    TEST_ASSERT_EQUAL_INT64(7, utc);
}

static void test_a_validity_window_converts_each_end_with_its_own_offset() {
    const UtcOffsetAt europe = zone("CET-1CEST,M3.5.0,M10.5.0/3");
    Validity validity;
    TEST_ASSERT_TRUE(latchkey_util::lockValidity(k2026Mar28TwentyTwoUtc, k2026Mar29TwentyTwoUtc, europe, validity));
    assertTime(LockTime{2026, 3, 28, 23, 0, 0}, validity.start);
    assertTime(LockTime{2026, 3, 30, 0, 0, 0}, validity.end);
}

static void test_a_validity_window_must_run_forward_within_the_lock_calendar() {
    Validity validity;
    TEST_ASSERT_FALSE(latchkey_util::lockValidity(k2026Nov8Noon, k2026Nov8Noon, fixed(0), validity));
    TEST_ASSERT_FALSE(latchkey_util::lockValidity(k2026Nov8Noon + 60, k2026Nov8Noon, fixed(0), validity));
    TEST_ASSERT_FALSE(latchkey_util::lockValidity(k2000 - 60, k2026Nov8Noon, fixed(0), validity));
    TEST_ASSERT_FALSE(latchkey_util::lockValidity(k2000, k2026Nov8Noon, fixed(-3600), validity));
    TEST_ASSERT_FALSE(latchkey_util::lockValidity(k2026Nov8Noon, k2100, fixed(0), validity));
    TEST_ASSERT_FALSE(latchkey_util::lockValidity(k2026Nov8Noon, k2099LastMinute, fixed(3600), validity));
    TEST_ASSERT_TRUE(latchkey_util::lockValidity(k2000, k2099LastMinute, fixed(0), validity));
    assertTime(LockTime{2000, 1, 1, 0, 0, 0}, validity.start);
    assertTime(LockTime{2099, 12, 31, 23, 59, 0}, validity.end);
}

static void test_a_window_ending_in_2099_is_permanent() {
    TEST_ASSERT_TRUE(latchkey_util::isPermanent(Validity{}));
    TEST_ASSERT_TRUE(latchkey_util::isPermanent(Validity{LockTime{2025, 3, 2, 10, 0, 0}, ttlock::kPermanentEnd}));
    TEST_ASSERT_FALSE(latchkey_util::isPermanent(Validity{ttlock::kPermanentStart, LockTime{2030, 1, 1, 0, 0, 0}}));
    TEST_ASSERT_FALSE(latchkey_util::isPermanent(Validity{ttlock::kPermanentStart, LockTime{2099, 1, 1, 0, 1, 0}}));
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_a_lock_time_counts_seconds_like_a_utc_calendar);
    RUN_TEST(test_a_time_that_cannot_exist_has_no_seconds);
    RUN_TEST(test_the_lock_is_given_local_time_at_that_instant);
    RUN_TEST(test_a_lock_time_maps_back_to_utc_with_its_own_offset);
    RUN_TEST(test_a_validity_window_converts_each_end_with_its_own_offset);
    RUN_TEST(test_a_validity_window_must_run_forward_within_the_lock_calendar);
    RUN_TEST(test_a_window_ending_in_2099_is_permanent);
    return UNITY_END();
}
