// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>
#include <initializer_list>
#include <optional>
#include <vector>

#include "latchkey_util/unlock_alert.h"
#include "latchkey_util/unlock_ledger.h"
#include "ttlock/types.h"

using latchkey_util::LatchkeyUnlock;
using latchkey_util::UnlockFinding;
using latchkey_util::UnlockLedger;
using latchkey_util::UnlockMethod;
using latchkey_util::UnlockVerdict;
using ttlock::LockTime;
using ttlock::LogEntry;

void setUp() {}

void tearDown() {}

static constexpr int64_t kTwoPm = 1762524000;
static constexpr int32_t kOffset = -3 * 3600;
static constexpr uint32_t kTolerance = 120;
static constexpr int64_t kKeep = 24 * 3600;
static constexpr size_t kCapacity = 4;

static LogEntry at(uint8_t type, int64_t secondsAfterTwoPm) {
    LogEntry log;
    log.type = type;
    const int64_t local = kTwoPm + kOffset + secondsAfterTwoPm;
    const int64_t secondOfDay = ((local % 86400) + 86400) % 86400;
    log.time = LockTime{2025, 11, 7, static_cast<uint8_t>(secondOfDay / 3600),
                        static_cast<uint8_t>(secondOfDay % 3600 / 60), static_cast<uint8_t>(secondOfDay % 60)};
    return log;
}

static LogEntry withRecord(uint8_t type, int64_t secondsAfterTwoPm, uint32_t recordId) {
    LogEntry log = at(type, secondsAfterTwoPm);
    log.recordId = recordId;
    return log;
}

static void assertVerdicts(std::initializer_list<UnlockVerdict> expected, const std::vector<UnlockFinding>& findings) {
    TEST_ASSERT_EQUAL_UINT(expected.size(), findings.size());
    size_t i = 0;
    for (UnlockVerdict verdict : expected) {
        TEST_ASSERT_EQUAL_INT_MESSAGE(static_cast<int>(verdict), static_cast<int>(findings[i].verdict),
                                      "verdict out of order");
        ++i;
    }
}

static std::vector<UnlockFinding> judge(UnlockLedger& ledger, const std::vector<LogEntry>& entries,
                                        int64_t now = kTwoPm + 30) {
    return ledger.judge(entries, kOffset, kTolerance, now);
}

static void test_the_classifier_says_which_unlocks_explained_an_entry() {
    std::vector<LatchkeyUnlock> performed(3);
    performed[0] = LatchkeyUnlock{kTwoPm + 600, kTwoPm + 602};
    performed[1] = LatchkeyUnlock{kTwoPm, kTwoPm + 2};
    performed[2] = LatchkeyUnlock{kTwoPm, kTwoPm + 2};
    std::vector<bool> used;
    const std::vector<UnlockFinding> findings =
        latchkey_util::classifyUnlocks({at(1, 1), at(4, 1)}, performed, kOffset, kTolerance, used);
    assertVerdicts({UnlockVerdict::Latchkey, UnlockVerdict::Reported}, findings);
    TEST_ASSERT_EQUAL_UINT(3, used.size());
    TEST_ASSERT_FALSE(used[0]);
    TEST_ASSERT_TRUE(used[1]);
    TEST_ASSERT_FALSE(used[2]);
}

static void test_a_noted_unlock_explains_its_entry_once() {
    UnlockLedger ledger(kCapacity, kKeep);
    ledger.note(kTwoPm, kTwoPm + 2);
    TEST_ASSERT_EQUAL_UINT(1, ledger.size());
    assertVerdicts({UnlockVerdict::Latchkey}, judge(ledger, {at(1, 1)}));
    TEST_ASSERT_EQUAL_UINT(0, ledger.size());
    assertVerdicts({UnlockVerdict::Alert}, judge(ledger, {at(1, 3)}));
}

static void test_a_foreign_app_unlock_and_a_forced_opening_alert() {
    UnlockLedger ledger(kCapacity, kKeep);
    ledger.note(kTwoPm, kTwoPm + 2);
    const std::vector<UnlockFinding> findings = judge(ledger, {at(1, 1), at(1, 40), at(29, 50), at(75, 3600)});
    assertVerdicts({UnlockVerdict::Latchkey, UnlockVerdict::Alert, UnlockVerdict::Alert, UnlockVerdict::Alert},
                   findings);
    TEST_ASSERT_EQUAL(UnlockMethod::Forced, findings[2].method);
    TEST_ASSERT_EQUAL(UnlockMethod::App, findings[3].method);
}

static void test_the_owners_own_unlocks_are_reported_and_keep_the_windows() {
    UnlockLedger ledger(kCapacity, kKeep);
    ledger.note(kTwoPm, kTwoPm + 2);
    assertVerdicts({UnlockVerdict::Reported, UnlockVerdict::Reported, UnlockVerdict::Reported,
                    UnlockVerdict::NotUnlock},
                   judge(ledger, {at(4, 1), at(20, 1), at(17, 1), at(26, 1)}));
    TEST_ASSERT_EQUAL_UINT(1, ledger.size());
}

static void test_windows_older_than_the_keep_time_are_dropped() {
    UnlockLedger ledger(kCapacity, kKeep);
    ledger.note(kTwoPm, kTwoPm + 2);
    assertVerdicts({UnlockVerdict::NotUnlock}, judge(ledger, {at(26, 1)}, kTwoPm + 2 + kKeep));
    TEST_ASSERT_EQUAL_UINT(1, ledger.size());
    assertVerdicts({UnlockVerdict::Alert}, judge(ledger, {at(1, 1)}, kTwoPm + 3 + kKeep));
    TEST_ASSERT_EQUAL_UINT(0, ledger.size());
}

static void test_the_ledger_keeps_the_newest_windows() {
    UnlockLedger ledger(kCapacity, kKeep);
    for (int64_t i = 0; i < 6; ++i) {
        ledger.note(kTwoPm + i * 1000, kTwoPm + i * 1000 + 2);
    }
    TEST_ASSERT_EQUAL_UINT(kCapacity, ledger.size());
    assertVerdicts({UnlockVerdict::Alert, UnlockVerdict::Alert, UnlockVerdict::Latchkey, UnlockVerdict::Latchkey,
                    UnlockVerdict::Latchkey, UnlockVerdict::Latchkey},
                   judge(ledger, {at(1, 1), at(1, 1001), at(1, 2001), at(1, 3001), at(1, 4001), at(1, 5001)},
                         kTwoPm + 6000));
}

static void test_the_boards_own_unlock_is_known_by_its_record_id_whatever_the_lock_clock_says() {
    UnlockLedger ledger(kCapacity, kKeep);
    const uint32_t sent = static_cast<uint32_t>(kTwoPm + 1);
    ledger.note(kTwoPm, kTwoPm + 2, sent);
    assertVerdicts({UnlockVerdict::Latchkey}, judge(ledger, {withRecord(1, 2 * 3600, sent)}));
    TEST_ASSERT_EQUAL_UINT(0, ledger.size());
}

static void test_a_foreign_unlock_inside_the_boards_window_alerts_when_its_record_id_differs() {
    UnlockLedger ledger(kCapacity, kKeep);
    const uint32_t sent = static_cast<uint32_t>(kTwoPm + 1);
    ledger.note(kTwoPm, kTwoPm + 2, sent);
    assertVerdicts({UnlockVerdict::Alert, UnlockVerdict::Latchkey, UnlockVerdict::Alert},
                   judge(ledger, {withRecord(1, 1, 999), withRecord(1, 1, sent), withRecord(1, 2, 0)}));
}

static void test_an_unlock_without_a_record_in_its_reply_is_known_by_its_window() {
    UnlockLedger ledger(kCapacity, kKeep);
    ledger.note(kTwoPm, kTwoPm + 2, std::nullopt);
    assertVerdicts({UnlockVerdict::Latchkey, UnlockVerdict::Alert},
                   judge(ledger, {withRecord(1, 1, 999), withRecord(1, 2, 1000)}));
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_the_classifier_says_which_unlocks_explained_an_entry);
    RUN_TEST(test_a_noted_unlock_explains_its_entry_once);
    RUN_TEST(test_a_foreign_app_unlock_and_a_forced_opening_alert);
    RUN_TEST(test_the_owners_own_unlocks_are_reported_and_keep_the_windows);
    RUN_TEST(test_windows_older_than_the_keep_time_are_dropped);
    RUN_TEST(test_the_ledger_keeps_the_newest_windows);
    RUN_TEST(test_the_boards_own_unlock_is_known_by_its_record_id_whatever_the_lock_clock_says);
    RUN_TEST(test_a_foreign_unlock_inside_the_boards_window_alerts_when_its_record_id_differs);
    RUN_TEST(test_an_unlock_without_a_record_in_its_reply_is_known_by_its_window);
    return UNITY_END();
}
