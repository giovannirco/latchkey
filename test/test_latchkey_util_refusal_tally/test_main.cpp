// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>
#include <vector>

#include "latchkey_util/refusal_tally.h"

using latchkey_util::RefusalCount;
using latchkey_util::RefusalTally;

void setUp() {}

void tearDown() {}

static constexpr int64_t kMinute = 60 * 1000;

static void assertCounts(const std::vector<RefusalCount>& counts, const char* kind, uint32_t count) {
    TEST_ASSERT_EQUAL_UINT(1, counts.size());
    TEST_ASSERT_EQUAL_STRING(kind, counts[0].kind.c_str());
    TEST_ASSERT_EQUAL_UINT32(count, counts[0].count);
}

static void test_the_first_refusal_of_a_kind_is_reported_at_once() {
    RefusalTally tally(kMinute);
    TEST_ASSERT_TRUE(tally.due(0).empty());
    tally.note("busy");
    assertCounts(tally.due(10), "busy", 1);
    TEST_ASSERT_TRUE(tally.due(20).empty());
}

static void test_later_refusals_wait_for_the_window_and_carry_their_count() {
    RefusalTally tally(kMinute);
    tally.note("busy");
    assertCounts(tally.due(0), "busy", 1);
    for (int i = 0; i < 5; ++i) {
        tally.note("busy");
    }
    TEST_ASSERT_TRUE(tally.due(kMinute - 1).empty());
    assertCounts(tally.due(kMinute), "busy", 5);
    TEST_ASSERT_TRUE(tally.due(3 * kMinute).empty());
    tally.note("busy", 7);
    assertCounts(tally.due(3 * kMinute), "busy", 7);
}

static void test_each_kind_has_its_own_window() {
    RefusalTally tally(kMinute);
    tally.note("busy");
    tally.note("dropped", 3);
    const std::vector<RefusalCount> first = tally.due(0);
    TEST_ASSERT_EQUAL_UINT(2, first.size());
    TEST_ASSERT_EQUAL_STRING("busy", first[0].kind.c_str());
    TEST_ASSERT_EQUAL_UINT32(1, first[0].count);
    TEST_ASSERT_EQUAL_STRING("dropped", first[1].kind.c_str());
    TEST_ASSERT_EQUAL_UINT32(3, first[1].count);
    tally.note("busy");
    tally.note("replayed");
    assertCounts(tally.due(1000), "replayed", 1);
    assertCounts(tally.due(kMinute), "busy", 1);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_the_first_refusal_of_a_kind_is_reported_at_once);
    RUN_TEST(test_later_refusals_wait_for_the_window_and_carry_their_count);
    RUN_TEST(test_each_kind_has_its_own_window);
    return UNITY_END();
}
