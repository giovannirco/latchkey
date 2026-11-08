// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <array>
#include <cstdint>

#include "latchkey_util/lock_watch.h"

using latchkey_util::ClockSync;
using latchkey_util::WatchState;

void setUp() {}

void tearDown() {}

static constexpr int64_t kNow = 1762524000;
static constexpr int32_t kBrasilia = -3 * 3600;
static constexpr int64_t kDay = 86400;

static WatchState watched() {
    WatchState state;
    state.baselined = true;
    state.cursor = 0x1234;
    state.clockKnown = true;
    state.clockOffset = kBrasilia;
    state.clockSetUtc = static_cast<uint32_t>(kNow);
    state.lastUtc = static_cast<uint32_t>(kNow - 1000);
    state.previousOffset = -2 * 3600;
    state.offsetSince = 0x1200;
    return state;
}

static void test_a_watch_state_encodes_byte_for_byte() {
    const std::array<uint8_t, latchkey_util::kWatchStateSize> expected{
        0x02, 0x03, 0x12, 0x34, 0xff, 0xff, 0xd5, 0xd0, 0x69, 0x0d, 0xfb,
        0x60, 0x69, 0x0d, 0xf7, 0x78, 0xff, 0xff, 0xe3, 0xe0, 0x12, 0x00};
    const std::array<uint8_t, latchkey_util::kWatchStateSize> bytes = latchkey_util::encodeWatchState(watched());
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected.data(), bytes.data(), bytes.size());
    std::array<uint8_t, latchkey_util::kWatchStateSize> blank{};
    blank[0] = 0x02;
    const std::array<uint8_t, latchkey_util::kWatchStateSize> fresh = latchkey_util::encodeWatchState(WatchState{});
    TEST_ASSERT_EQUAL_UINT8_ARRAY(blank.data(), fresh.data(), fresh.size());
}

static void test_a_watch_state_decodes_back() {
    const std::array<uint8_t, latchkey_util::kWatchStateSize> bytes = latchkey_util::encodeWatchState(watched());
    WatchState out;
    TEST_ASSERT_TRUE(latchkey_util::decodeWatchState(bytes.data(), bytes.size(), out));
    TEST_ASSERT_TRUE(out == watched());
    WatchState east = watched();
    east.clockOffset = 19800;
    east.baselined = false;
    const std::array<uint8_t, latchkey_util::kWatchStateSize> eastBytes = latchkey_util::encodeWatchState(east);
    TEST_ASSERT_TRUE(latchkey_util::decodeWatchState(eastBytes.data(), eastBytes.size(), out));
    TEST_ASSERT_TRUE(out == east);
}

static void test_a_watch_state_stored_by_the_first_layout_still_reads() {
    const uint8_t first[] = {0x01, 0x03, 0x12, 0x34, 0xff, 0xff, 0xd5, 0xd0,
                             0x69, 0x0d, 0xfb, 0x60, 0x69, 0x0d, 0xf7, 0x78};
    WatchState out;
    TEST_ASSERT_TRUE(latchkey_util::decodeWatchState(first, sizeof(first), out));
    WatchState expected = watched();
    expected.previousOffset = kBrasilia;
    expected.offsetSince = 0;
    TEST_ASSERT_TRUE(out == expected);
}

static void test_a_damaged_watch_state_is_refused() {
    std::array<uint8_t, latchkey_util::kWatchStateSize> bytes = latchkey_util::encodeWatchState(watched());
    WatchState out;
    out.cursor = 7;
    TEST_ASSERT_FALSE(latchkey_util::decodeWatchState(bytes.data(), bytes.size() - 1, out));
    TEST_ASSERT_FALSE(latchkey_util::decodeWatchState(nullptr, bytes.size(), out));
    TEST_ASSERT_FALSE(latchkey_util::decodeWatchState(bytes.data(), 16, out));
    bytes[0] = 3;
    TEST_ASSERT_FALSE(latchkey_util::decodeWatchState(bytes.data(), bytes.size(), out));
    bytes[0] = 1;
    TEST_ASSERT_FALSE(latchkey_util::decodeWatchState(bytes.data(), bytes.size(), out));
    bytes[0] = 2;
    bytes[1] = 0x07;
    TEST_ASSERT_FALSE(latchkey_util::decodeWatchState(bytes.data(), bytes.size(), out));
    TEST_ASSERT_EQUAL_UINT16(7, out.cursor);
}

static void test_a_lock_clock_the_board_never_set_is_set_at_once() {
    TEST_ASSERT_EQUAL(ClockSync::Now, latchkey_util::clockSyncNeeded(WatchState{}, kBrasilia, kNow, kDay));
}

static void test_a_new_offset_sets_the_lock_clock_at_once() {
    const WatchState state = watched();
    TEST_ASSERT_EQUAL(ClockSync::None, latchkey_util::clockSyncNeeded(state, kBrasilia, kNow + 60, kDay));
    TEST_ASSERT_EQUAL(ClockSync::Now, latchkey_util::clockSyncNeeded(state, kBrasilia + 3600, kNow + 60, kDay));
    TEST_ASSERT_EQUAL(ClockSync::Now, latchkey_util::clockSyncNeeded(state, 0, kNow + 60, kDay));
}

static void test_drift_is_corrected_once_a_day_when_a_link_is_open_anyway() {
    const WatchState state = watched();
    TEST_ASSERT_EQUAL(ClockSync::None, latchkey_util::clockSyncNeeded(state, kBrasilia, kNow + kDay - 1, kDay));
    TEST_ASSERT_EQUAL(ClockSync::Soon, latchkey_util::clockSyncNeeded(state, kBrasilia, kNow + kDay, kDay));
    TEST_ASSERT_EQUAL(ClockSync::Soon, latchkey_util::clockSyncNeeded(state, kBrasilia, kNow - 1, kDay));
}

static void test_setting_the_clock_keeps_the_offset_of_the_records_before() {
    WatchState state;
    state.baselined = true;
    state.cursor = 100;
    latchkey_util::clockSet(state, kBrasilia, kNow);
    TEST_ASSERT_TRUE(state.clockKnown);
    TEST_ASSERT_EQUAL_INT32(kBrasilia, state.clockOffset);
    TEST_ASSERT_EQUAL_INT32(kBrasilia, state.previousOffset);
    TEST_ASSERT_EQUAL_UINT32(kNow, state.clockSetUtc);
    state.cursor = 140;
    latchkey_util::clockSet(state, kBrasilia + 3600, kNow + kDay);
    TEST_ASSERT_EQUAL_INT32(kBrasilia + 3600, state.clockOffset);
    TEST_ASSERT_EQUAL_INT32(kBrasilia, state.previousOffset);
    TEST_ASSERT_EQUAL_UINT16(140, state.offsetSince);
    TEST_ASSERT_EQUAL_INT32(kBrasilia, latchkey_util::recordOffset(state, 139, 0));
    TEST_ASSERT_EQUAL_INT32(kBrasilia + 3600, latchkey_util::recordOffset(state, 140, 0));
    TEST_ASSERT_EQUAL_INT32(kBrasilia + 3600, latchkey_util::recordOffset(state, 200, 0));
    TEST_ASSERT_EQUAL_INT32(19800, latchkey_util::recordOffset(WatchState{}, 5, 19800));
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_a_watch_state_encodes_byte_for_byte);
    RUN_TEST(test_a_watch_state_decodes_back);
    RUN_TEST(test_a_watch_state_stored_by_the_first_layout_still_reads);
    RUN_TEST(test_a_damaged_watch_state_is_refused);
    RUN_TEST(test_setting_the_clock_keeps_the_offset_of_the_records_before);
    RUN_TEST(test_a_lock_clock_the_board_never_set_is_set_at_once);
    RUN_TEST(test_a_new_offset_sets_the_lock_clock_at_once);
    RUN_TEST(test_drift_is_corrected_once_a_day_when_a_link_is_open_anyway);
    return UNITY_END();
}
