// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>
#include <vector>

#include "latchkey_util/log_watch.h"
#include "latchkey_util/unlock_alert.h"
#include "ttlock/commands.h"
#include "ttlock/types.h"

using latchkey_util::LogWatch;
using latchkey_util::PageJudgement;
using latchkey_util::UnlockVerdict;
using ttlock::LockTime;
using ttlock::LogEntry;
using ttlock::LogPage;

void setUp() {}

void tearDown() {}

static constexpr int64_t kTwoPm = 1762524000;
static constexpr int32_t kOffset = -3 * 3600;
static constexpr uint32_t kTolerance = 120;

static LogEntry unlockAt(uint16_t seq, int64_t secondsAfterTwoPm, uint32_t recordId) {
    LogEntry log;
    log.recordNumber = seq;
    log.type = 1;
    const int64_t local = kTwoPm + kOffset + secondsAfterTwoPm;
    const int64_t second = local % 86400;
    log.time = LockTime{2025, 11, 7, static_cast<uint8_t>(second / 3600), static_cast<uint8_t>(second % 3600 / 60),
                        static_cast<uint8_t>(second % 60)};
    log.recordId = recordId;
    log.credential = "1234567";
    return log;
}

static LogPage page(uint16_t sequence, std::vector<LogEntry> entries) {
    LogPage out;
    out.sequence = sequence;
    out.entries = std::move(entries);
    return out;
}

static LogWatch watching(uint16_t cursor) {
    LogWatch watch(16, 24 * 3600);
    watch.state().baselined = true;
    watch.state().cursor = cursor;
    latchkey_util::clockSet(watch.state(), kOffset, kTwoPm - 3600);
    watch.state().lastUtc = static_cast<uint32_t>(kTwoPm);
    return watch;
}

static PageJudgement read(LogWatch& watch, const LogPage& logPage) {
    return watch.readPage(logPage, 0, kTolerance, kTwoPm + 60);
}

static void test_a_judged_page_moves_the_cursor_and_uses_up_the_unlock_together() {
    LogWatch watch = watching(154);
    const uint32_t sent = static_cast<uint32_t>(kTwoPm + 1);
    watch.noteUnlock(kTwoPm, kTwoPm + 2, sent);
    const LogPage logged = page(155, {unlockAt(154, 1, sent)});
    const PageJudgement first = read(watch, logged);
    TEST_ASSERT_EQUAL_UINT(1, first.fresh.size());
    TEST_ASSERT_EQUAL(UnlockVerdict::Latchkey, first.findings[0].verdict);
    TEST_ASSERT_EQUAL_UINT16(155, watch.state().cursor);
    TEST_ASSERT_EQUAL_UINT(0, watch.unlocks());
    const LogWatch kept = watch;
    LogWatch again = kept;
    const PageJudgement second = read(again, logged);
    TEST_ASSERT_EQUAL_UINT(0, second.fresh.size());
    TEST_ASSERT_EQUAL_UINT(0, second.findings.size());
    TEST_ASSERT_FALSE(second.more);
}

static void test_an_unexplained_app_unlock_in_a_page_is_an_alert() {
    LogWatch watch = watching(10);
    const PageJudgement judged = read(watch, page(11, {unlockAt(10, 5, 4242)}));
    TEST_ASSERT_EQUAL_UINT(1, judged.findings.size());
    TEST_ASSERT_EQUAL(UnlockVerdict::Alert, judged.findings[0].verdict);
    TEST_ASSERT_TRUE(judged.more);
}

static void test_the_end_of_the_log_judges_nothing_and_keeps_the_unlocks() {
    LogWatch watch = watching(170);
    watch.noteUnlock(kTwoPm, kTwoPm + 2, std::nullopt);
    for (const LogPage& end : {page(0, {}), page(1, {unlockAt(0, -3600, 1)})}) {
        const PageJudgement judged = read(watch, end);
        TEST_ASSERT_EQUAL_UINT(0, judged.findings.size());
        TEST_ASSERT_FALSE(judged.more);
    }
    TEST_ASSERT_EQUAL_UINT16(170, watch.state().cursor);
    TEST_ASSERT_EQUAL_UINT(1, watch.unlocks());
}

static void test_a_lock_clock_the_board_never_set_is_read_with_the_offset_given() {
    LogWatch watch(16, 24 * 3600);
    watch.state().baselined = true;
    watch.state().cursor = 3;
    watch.noteUnlock(kTwoPm - 3 * 3600, kTwoPm - 3 * 3600 + 2, std::nullopt);
    const PageJudgement judged = watch.readPage(page(4, {unlockAt(3, 1, 7)}), 0, kTolerance, kTwoPm);
    TEST_ASSERT_EQUAL(UnlockVerdict::Latchkey, judged.findings[0].verdict);
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_a_judged_page_moves_the_cursor_and_uses_up_the_unlock_together);
    RUN_TEST(test_an_unexplained_app_unlock_in_a_page_is_an_alert);
    RUN_TEST(test_the_end_of_the_log_judges_nothing_and_keeps_the_unlocks);
    RUN_TEST(test_a_lock_clock_the_board_never_set_is_read_with_the_offset_given);
    return UNITY_END();
}
