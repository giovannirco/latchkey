// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>
#include <cstdio>
#include <string>

#include "latchkey_util/tz.h"

using latchkey_util::TimeZone;

void setUp() {}

void tearDown() {}

struct Instant {
    int64_t utc;
    int32_t offset;
};

static TimeZone parsed(const char* text) {
    TimeZone zone;
    TEST_ASSERT_TRUE_MESSAGE(latchkey_util::parseTimeZone(text, zone), text);
    return zone;
}

template <size_t N>
static void assertOffsets(const char* text, const Instant (&instants)[N]) {
    const TimeZone zone = parsed(text);
    for (const Instant& instant : instants) {
        char label[96];
        snprintf(label, sizeof(label), "%s at %lld", text, static_cast<long long>(instant.utc));
        TEST_ASSERT_EQUAL_INT32_MESSAGE(instant.offset, latchkey_util::utcOffsetAt(zone, instant.utc), label);
    }
}

static void assertInvalid(const std::string& text) {
    TimeZone zone;
    TEST_ASSERT_FALSE_MESSAGE(latchkey_util::parseTimeZone(text, zone), text.c_str());
}

static void test_brief_examples_are_valid() {
    parsed("BRT3");
    parsed("CET-1CEST,M3.5.0,M10.5.0/3");
    parsed("UTC0");
}

static void test_fixed_offsets() {
    assertOffsets("BRT3", {{1768478400, -10800}, {1784116800, -10800}});
    assertOffsets("UTC0", {{1768478400, 0}});
    assertOffsets("EST+5", {{1768478400, -18000}});
    assertOffsets("XYZ-14", {{1768478400, 50400}});
    assertOffsets("<-03>3", {{1768478400, -10800}});
    assertOffsets("<+0545>-5:45", {{1768478400, 20700}});
}

static void test_central_europe_switches_on_the_last_sundays() {
    assertOffsets("CET-1CEST,M3.5.0,M10.5.0/3", {{1768478400, 3600},
                                                  {1784116800, 7200},
                                                  {1774745999, 3600},
                                                  {1774746000, 7200},
                                                  {1792889999, 7200},
                                                  {1792890000, 3600},
                                                  {1806195599, 3600},
                                                  {1806195600, 7200}});
}

static void test_western_europe_switches_at_one_utc() {
    assertOffsets("WET0WEST,M3.5.0/1,M10.5.0",
                  {{1774745999, 0}, {1774746000, 3600}, {1792889999, 3600}, {1792890000, 0}});
}

static void test_southern_hemisphere_daylight_spans_the_new_year() {
    assertOffsets("AEST-10AEDT,M10.1.0,M4.1.0/3", {{1768478400, 39600},
                                                    {1784116800, 36000},
                                                    {1775318399, 39600},
                                                    {1775318400, 36000},
                                                    {1791043199, 36000},
                                                    {1791043200, 39600},
                                                    {1798759800, 39600}});
    assertOffsets("NZST-12NZDT,M9.5.0,M4.1.0/3",
                  {{1775311199, 46800}, {1775311200, 43200}, {1790431199, 43200}, {1790431200, 46800}});
}

static void test_quoted_names_and_explicit_daylight_offsets() {
    assertOffsets("<+1245>-12:45<+1345>,M9.5.0/2:45,M4.1.0/3:45", {{1768435200, 49500},
                                                                    {1784073600, 45900},
                                                                    {1775311199, 49500},
                                                                    {1775311200, 45900},
                                                                    {1790431199, 45900},
                                                                    {1790431200, 49500}});
}

static void test_transition_times_beyond_24_hours() {
    assertOffsets("IST-2IDT,M3.4.4/26,M10.5.0",
                  {{1774569599, 7200}, {1774569600, 10800}, {1792882799, 10800}, {1792882800, 7200}});
}

static void test_negative_transition_times() {
    assertOffsets("<-02>2<-01>,M3.5.0/-1,M10.5.0/0",
                  {{1774745999, -7200}, {1774746000, -3600}, {1792889999, -3600}, {1792890000, -7200}});
    assertOffsets("<-03>3<-02>,M3.5.0/-2,M10.5.0/-1",
                  {{1774745999, -10800}, {1774746000, -7200}, {1792889999, -7200}, {1792890000, -10800}});
}

static void test_julian_days_skip_february_29() {
    assertOffsets("EST5EDT,J60,J300", {{1772348399, -18000},
                                        {1772348400, -14400},
                                        {1835506799, -18000},
                                        {1835506800, -14400},
                                        {1856239199, -14400},
                                        {1856239200, -18000}});
}

static void test_zero_based_days_count_february_29() {
    assertOffsets("EST5EDT,59,299", {{1772348399, -18000},
                                      {1772348400, -14400},
                                      {1835420399, -18000},
                                      {1835420400, -14400},
                                      {1856152799, -14400},
                                      {1856152800, -18000}});
}

static void test_daylight_all_year() {
    assertOffsets("EST5EDT,0/0,J365/25", {{1767225600, -14400}, {1782864000, -14400}, {1798761599, -14400}});
}

static void test_garbage_is_invalid() {
    assertInvalid("");
    assertInvalid("garbage");
    assertInvalid("BRT");
    assertInvalid("BR3");
    assertInvalid("B1T3");
    assertInvalid("BRT3X");
    assertInvalid("BRT3 ");
    assertInvalid(" BRT3");
    assertInvalid("3");
    assertInvalid("<+03");
    assertInvalid("<AB>3");
    assertInvalid("<A_B>3");
    assertInvalid("UTC25");
    assertInvalid("UTC-25");
    assertInvalid("BRT3:60");
    assertInvalid("BRT3:00:60");
    assertInvalid("BRT3:0");
    assertInvalid("BRT3:00:30");
    assertInvalid("BRT+");
}

static void test_daylight_needs_both_rules() {
    assertInvalid("CET-1CEST");
    assertInvalid("CET-1CEST,M3.5.0");
    assertInvalid("CET-1CEST,M3.5.0,");
    assertInvalid("CET-1CEST,,M10.5.0");
    assertInvalid("CET-1CEST-2");
}

static void test_rule_fields_are_range_checked() {
    assertInvalid("CET-1CEST,M0.5.0,M10.5.0");
    assertInvalid("CET-1CEST,M13.5.0,M10.5.0");
    assertInvalid("CET-1CEST,M3.0.0,M10.5.0");
    assertInvalid("CET-1CEST,M3.6.0,M10.5.0");
    assertInvalid("CET-1CEST,M3.5.7,M10.5.0");
    assertInvalid("CET-1CEST,M3.5,M10.5.0");
    assertInvalid("CET-1CEST,M3.5.0/168,M10.5.0");
    assertInvalid("CET-1CEST,M3.5.0/-168,M10.5.0");
    assertInvalid("CET-1CEST,M3.5.0/2:60,M10.5.0");
    assertInvalid("EST5EDT,J0,J300");
    assertInvalid("EST5EDT,J366,J300");
    assertInvalid("EST5EDT,366,299");
    assertInvalid("EST5EDT,M3.2.0,M11.1.0,M12.1.0");
}

static void test_offsets_stay_below_24_hours() {
    assertOffsets("XXX23:59", {{1768478400, -86340}});
    assertOffsets("XXX-23:59", {{1768478400, 86340}});
    assertInvalid("UTC24");
    assertInvalid("UTC-24");
    assertInvalid("UTC+24:00");
    assertInvalid("CET-1CEST-24,M3.5.0,M10.5.0/3");
    assertInvalid("XXX-23YYY,M3.5.0,M10.5.0");
    parsed("XXX23YYY,M3.5.0,M10.5.0");
}

static void test_length_is_capped() {
    const std::string longest = "<" + std::string(latchkey_util::kMaxTimeZoneLength - 3, 'A') + ">0";
    TEST_ASSERT_EQUAL_size_t(latchkey_util::kMaxTimeZoneLength, longest.size());
    parsed(longest.c_str());
    assertInvalid("<" + std::string(latchkey_util::kMaxTimeZoneLength - 2, 'A') + ">0");
}

static void test_local_timestamps_carry_the_offset() {
    TEST_ASSERT_EQUAL_STRING("2026-01-15T09:00:00-03:00", latchkey_util::localTimestamp(1768478400, -10800).c_str());
    TEST_ASSERT_EQUAL_STRING("2026-01-15T17:45:00+05:45", latchkey_util::localTimestamp(1768478400, 20700).c_str());
    TEST_ASSERT_EQUAL_STRING("2026-01-15T12:00:00+00:00", latchkey_util::localTimestamp(1768478400, 0).c_str());
    TEST_ASSERT_EQUAL_STRING("2027-01-01T00:59:59+01:00", latchkey_util::localTimestamp(1798761599, 3600).c_str());
    TEST_ASSERT_EQUAL_STRING("2028-02-29T07:30:00-04:30", latchkey_util::localTimestamp(1835438400, -16200).c_str());
    TEST_ASSERT_EQUAL_STRING("2024-02-29T12:00:00+00:00", latchkey_util::localTimestamp(1709208000, 0).c_str());
    TEST_ASSERT_EQUAL_STRING("2100-01-01T14:00:00+14:00", latchkey_util::localTimestamp(4102444800, 50400).c_str());
    TEST_ASSERT_EQUAL_STRING("1970-01-01T00:00:00+00:00", latchkey_util::localTimestamp(0, 0).c_str());
    TEST_ASSERT_EQUAL_STRING("1969-12-31T23:00:00-01:00", latchkey_util::localTimestamp(0, -3600).c_str());
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_brief_examples_are_valid);
    RUN_TEST(test_fixed_offsets);
    RUN_TEST(test_central_europe_switches_on_the_last_sundays);
    RUN_TEST(test_western_europe_switches_at_one_utc);
    RUN_TEST(test_southern_hemisphere_daylight_spans_the_new_year);
    RUN_TEST(test_quoted_names_and_explicit_daylight_offsets);
    RUN_TEST(test_transition_times_beyond_24_hours);
    RUN_TEST(test_negative_transition_times);
    RUN_TEST(test_julian_days_skip_february_29);
    RUN_TEST(test_zero_based_days_count_february_29);
    RUN_TEST(test_daylight_all_year);
    RUN_TEST(test_garbage_is_invalid);
    RUN_TEST(test_daylight_needs_both_rules);
    RUN_TEST(test_rule_fields_are_range_checked);
    RUN_TEST(test_offsets_stay_below_24_hours);
    RUN_TEST(test_length_is_capped);
    RUN_TEST(test_local_timestamps_carry_the_offset);
    return UNITY_END();
}
