// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>
#include <initializer_list>
#include <vector>

#include "latchkey_util/unlock_alert.h"
#include "ttlock/types.h"

using latchkey_util::LatchkeyUnlock;
using latchkey_util::UnlockFinding;
using latchkey_util::UnlockMethod;
using latchkey_util::UnlockVerdict;
using ttlock::LockTime;
using ttlock::LogEntry;

void setUp() {}

void tearDown() {}

static constexpr int64_t kTwoPm = 1762524000;
static constexpr int32_t kOffset = -3 * 3600;
static constexpr uint32_t kTolerance = 60;
static const LockTime kElevenLocal{2025, 11, 7, 11, 0, 0};

static LockTime localAt(int64_t secondsAfterEleven) {
    LockTime time = kElevenLocal;
    time.minute = static_cast<uint8_t>(secondsAfterEleven / 60);
    time.second = static_cast<uint8_t>(secondsAfterEleven % 60);
    return time;
}

static LogEntry entry(uint8_t type, const LockTime& time, uint32_t recordId = 0) {
    LogEntry log;
    log.type = type;
    log.time = time;
    log.recordId = recordId;
    return log;
}

static LatchkeyUnlock sent(int64_t from, int64_t to, UnlockMethod method = UnlockMethod::App) {
    LatchkeyUnlock unlock;
    unlock.fromUtc = from;
    unlock.toUtc = to;
    unlock.method = method;
    return unlock;
}

static LatchkeyUnlock sentWithRecord(int64_t from, int64_t to, uint32_t recordId) {
    LatchkeyUnlock unlock = sent(from, to);
    unlock.recordId = recordId;
    return unlock;
}

static std::vector<UnlockFinding> classify(const std::vector<LogEntry>& entries,
                                           const std::vector<LatchkeyUnlock>& performed,
                                           int32_t offset = kOffset) {
    const std::vector<UnlockFinding> findings = latchkey_util::classifyUnlocks(entries, performed, offset, kTolerance);
    TEST_ASSERT_EQUAL_UINT(entries.size(), findings.size());
    return findings;
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

static void test_record_types_map_to_unlock_methods() {
    const struct {
        uint8_t type;
        UnlockMethod method;
        const char* name;
    } cases[] = {
        {1, UnlockMethod::App, "app"},
        {75, UnlockMethod::App, "app"},
        {77, UnlockMethod::App, "app"},
        {3, UnlockMethod::Remote, "remote"},
        {28, UnlockMethod::Remote, "remote"},
        {76, UnlockMethod::Remote, "remote"},
        {4, UnlockMethod::Passcode, "passcode"},
        {78, UnlockMethod::Passcode, "passcode"},
        {92, UnlockMethod::Passcode, "passcode"},
        {20, UnlockMethod::Fingerprint, "fingerprint"},
        {79, UnlockMethod::Fingerprint, "fingerprint"},
        {17, UnlockMethod::Card, "card"},
        {80, UnlockMethod::Card, "card"},
        {27, UnlockMethod::MechanicalKey, "key"},
        {19, UnlockMethod::Wristband, "wristband"},
        {29, UnlockMethod::Forced, "forced"},
        {57, UnlockMethod::Other, "other"},
        {67, UnlockMethod::Other, "other"},
        {84, UnlockMethod::Other, "other"},
        {94, UnlockMethod::Other, "other"},
        {111, UnlockMethod::Other, "other"},
        {26, UnlockMethod::None, "none"},
        {7, UnlockMethod::None, "none"},
        {14, UnlockMethod::None, "none"},
        {31, UnlockMethod::None, "none"},
        {37, UnlockMethod::None, "none"},
        {41, UnlockMethod::None, "none"},
        {0, UnlockMethod::None, "none"},
        {255, UnlockMethod::None, "none"},
    };
    for (const auto& c : cases) {
        TEST_ASSERT_EQUAL_INT_MESSAGE(static_cast<int>(c.method), static_cast<int>(latchkey_util::unlockMethodOf(c.type)),
                                      c.name);
        TEST_ASSERT_EQUAL_STRING(c.name, latchkey_util::toString(latchkey_util::unlockMethodOf(c.type)));
    }
}

static void test_an_app_unlock_inside_a_latchkey_window_is_latchkey() {
    const std::vector<UnlockFinding> findings = classify({entry(1, localAt(2))}, {sent(kTwoPm, kTwoPm + 3)});
    TEST_ASSERT_EQUAL(UnlockMethod::App, findings[0].method);
    TEST_ASSERT_EQUAL(UnlockVerdict::Latchkey, findings[0].verdict);
}

static void test_an_app_unlock_nobody_explains_is_an_alert() {
    assertVerdicts({UnlockVerdict::Alert}, classify({entry(1, localAt(2))}, {}));
    assertVerdicts({UnlockVerdict::Alert}, classify({entry(1, localAt(2))}, {sent(kTwoPm + 600, kTwoPm + 603)}));
    const std::vector<UnlockFinding> findings = classify({entry(75, localAt(2))}, {});
    TEST_ASSERT_EQUAL(UnlockMethod::App, findings[0].method);
    TEST_ASSERT_EQUAL(UnlockVerdict::Alert, findings[0].verdict);
}

static void test_the_tolerance_widens_the_window_and_no_more() {
    const LatchkeyUnlock window = sent(kTwoPm + 100, kTwoPm + 110);
    assertVerdicts({UnlockVerdict::Latchkey}, classify({entry(1, localAt(100 - 60))}, {window}));
    assertVerdicts({UnlockVerdict::Alert}, classify({entry(1, localAt(100 - 61))}, {window}));
    assertVerdicts({UnlockVerdict::Latchkey}, classify({entry(1, localAt(110 + 60))}, {window}));
    assertVerdicts({UnlockVerdict::Alert}, classify({entry(1, localAt(110 + 61))}, {window}));
}

static void test_one_latchkey_unlock_explains_one_entry() {
    assertVerdicts({UnlockVerdict::Latchkey, UnlockVerdict::Alert},
                   classify({entry(1, localAt(2)), entry(1, localAt(3))}, {sent(kTwoPm, kTwoPm + 5)}));
    assertVerdicts({UnlockVerdict::Latchkey, UnlockVerdict::Latchkey},
                   classify({entry(1, localAt(2)), entry(1, localAt(3))},
                            {sent(kTwoPm, kTwoPm + 5), sent(kTwoPm, kTwoPm + 5)}));
}

static void test_a_record_id_picks_the_entry_latchkey_made() {
    const LatchkeyUnlock ours = sentWithRecord(kTwoPm, kTwoPm + 5, 42);
    assertVerdicts({UnlockVerdict::Alert, UnlockVerdict::Latchkey},
                   classify({entry(1, localAt(2), 41), entry(1, localAt(3), 42)}, {ours}));
    assertVerdicts({UnlockVerdict::Latchkey, UnlockVerdict::Alert},
                   classify({entry(1, localAt(3), 42), entry(1, localAt(2), 41)}, {ours}));
    assertVerdicts({UnlockVerdict::Alert}, classify({entry(1, localAt(2), 7)}, {ours}));
    assertVerdicts({UnlockVerdict::Alert}, classify({entry(1, localAt(600), 42)}, {ours}));
    assertVerdicts({UnlockVerdict::Latchkey, UnlockVerdict::Latchkey},
                   classify({entry(1, localAt(2), 41), entry(1, localAt(3), 42)}, {sent(kTwoPm, kTwoPm + 5), ours}));
}

static void test_a_record_id_that_differs_from_the_log_alerts_even_inside_the_window() {
    const LogEntry logged = entry(1, localAt(2), 7);
    assertVerdicts({UnlockVerdict::Alert}, classify({logged}, {sentWithRecord(kTwoPm, kTwoPm + 5, 42)}));
    assertVerdicts({UnlockVerdict::Latchkey}, classify({logged}, {sent(kTwoPm, kTwoPm + 5)}));
    assertVerdicts({UnlockVerdict::Alert, UnlockVerdict::Alert},
                   classify({logged, entry(1, localAt(3), 8)}, {sentWithRecord(kTwoPm, kTwoPm + 5, 42),
                                                                sentWithRecord(kTwoPm, kTwoPm + 5, 43)}));
}

static void test_remote_unlocks_need_a_remote_action() {
    const std::vector<UnlockFinding> alone = classify({entry(28, localAt(2))}, {sent(kTwoPm, kTwoPm + 5)});
    TEST_ASSERT_EQUAL(UnlockMethod::Remote, alone[0].method);
    TEST_ASSERT_EQUAL(UnlockVerdict::Alert, alone[0].verdict);
    assertVerdicts({UnlockVerdict::Latchkey},
                   classify({entry(28, localAt(2))}, {sent(kTwoPm, kTwoPm + 5, UnlockMethod::Remote)}));
    assertVerdicts({UnlockVerdict::Alert},
                   classify({entry(1, localAt(2))}, {sent(kTwoPm, kTwoPm + 5, UnlockMethod::Remote)}));
}

static void test_keypad_fingerprint_card_and_key_unlocks_are_reported_not_alerts() {
    const std::vector<UnlockFinding> findings =
        classify({entry(4, localAt(2)), entry(20, localAt(3)), entry(17, localAt(4)), entry(27, localAt(5)),
                  entry(92, localAt(6)), entry(19, localAt(7))},
                 {});
    const UnlockMethod methods[] = {UnlockMethod::Passcode, UnlockMethod::Fingerprint, UnlockMethod::Card,
                                    UnlockMethod::MechanicalKey, UnlockMethod::Passcode, UnlockMethod::Wristband};
    for (size_t i = 0; i < findings.size(); ++i) {
        TEST_ASSERT_EQUAL(methods[i], findings[i].method);
        TEST_ASSERT_EQUAL(UnlockVerdict::Reported, findings[i].verdict);
    }
    assertVerdicts({UnlockVerdict::Reported, UnlockVerdict::Alert},
                   classify({entry(4, localAt(2)), entry(1, localAt(3))}, {sent(kTwoPm + 900, kTwoPm + 905)}));
}

static void test_a_forced_open_entry_is_always_an_alert() {
    const std::vector<UnlockFinding> alone = classify({entry(29, localAt(2))}, {});
    TEST_ASSERT_EQUAL(UnlockMethod::Forced, alone[0].method);
    TEST_ASSERT_EQUAL(UnlockVerdict::Alert, alone[0].verdict);
    assertVerdicts({UnlockVerdict::Alert, UnlockVerdict::Latchkey},
                   classify({entry(29, localAt(2)), entry(1, localAt(3))}, {sent(kTwoPm, kTwoPm + 5)}));
    assertVerdicts({UnlockVerdict::Alert},
                   classify({entry(29, localAt(2))}, {sent(kTwoPm, kTwoPm + 5, UnlockMethod::Forced)}));
    assertVerdicts({UnlockVerdict::Alert}, classify({entry(29, LockTime{2025, 13, 7, 11, 0, 0})}, {}));
}

static void test_entries_that_are_not_unlocks() {
    const std::vector<UnlockFinding> findings =
        classify({entry(26, localAt(2)), entry(7, localAt(3)), entry(14, localAt(4)), entry(31, localAt(5))},
                 {sent(kTwoPm, kTwoPm + 10)});
    for (const UnlockFinding& finding : findings) {
        TEST_ASSERT_EQUAL(UnlockMethod::None, finding.method);
        TEST_ASSERT_EQUAL(UnlockVerdict::NotUnlock, finding.verdict);
    }
}

static void test_lock_times_are_read_with_the_lock_offset() {
    assertVerdicts({UnlockVerdict::Latchkey}, classify({entry(1, localAt(2))}, {sent(kTwoPm, kTwoPm + 5)}, kOffset));
    assertVerdicts({UnlockVerdict::Alert}, classify({entry(1, localAt(2))}, {sent(kTwoPm, kTwoPm + 5)}, 0));
    assertVerdicts({UnlockVerdict::Latchkey},
                   classify({entry(1, localAt(2))}, {sent(kTwoPm - 3 * 3600, kTwoPm - 3 * 3600 + 5)}, 0));
    const LockTime newYear{2026, 1, 1, 0, 0, 30};
    assertVerdicts({UnlockVerdict::Latchkey},
                   classify({entry(1, newYear)}, {sent(1767225630 - 2, 1767225630 + 2)}, 0));
    const LockTime leapDay{2028, 2, 29, 23, 59, 59};
    assertVerdicts({UnlockVerdict::Latchkey},
                   classify({entry(1, leapDay)}, {sent(1835481599 + 3600, 1835481599 + 3600)}, -3600));
    assertVerdicts({UnlockVerdict::Alert},
                   classify({entry(1, leapDay)}, {sent(1835481599 + 3600 + 61, 1835481599 + 3600 + 61)}, -3600));
}

static void test_an_entry_time_that_cannot_exist_is_never_explained() {
    const LatchkeyUnlock always = sent(0, 4102444800);
    for (const LockTime& time : {LockTime{2025, 0, 7, 11, 0, 0}, LockTime{2025, 13, 7, 11, 0, 0},
                                 LockTime{2025, 11, 0, 11, 0, 0}, LockTime{2025, 11, 31, 11, 0, 0},
                                 LockTime{2025, 2, 29, 11, 0, 0}, LockTime{2025, 11, 7, 24, 0, 0},
                                 LockTime{2025, 11, 7, 11, 60, 0}, LockTime{2025, 11, 7, 11, 0, 60}}) {
        const std::vector<UnlockFinding> findings = classify({entry(1, time)}, {always});
        TEST_ASSERT_EQUAL(UnlockVerdict::Alert, findings[0].verdict);
    }
    assertVerdicts({UnlockVerdict::Reported}, classify({entry(4, LockTime{2025, 13, 7, 11, 0, 0})}, {always}));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_record_types_map_to_unlock_methods);
    RUN_TEST(test_an_app_unlock_inside_a_latchkey_window_is_latchkey);
    RUN_TEST(test_an_app_unlock_nobody_explains_is_an_alert);
    RUN_TEST(test_the_tolerance_widens_the_window_and_no_more);
    RUN_TEST(test_one_latchkey_unlock_explains_one_entry);
    RUN_TEST(test_a_record_id_picks_the_entry_latchkey_made);
    RUN_TEST(test_a_record_id_that_differs_from_the_log_alerts_even_inside_the_window);
    RUN_TEST(test_remote_unlocks_need_a_remote_action);
    RUN_TEST(test_keypad_fingerprint_card_and_key_unlocks_are_reported_not_alerts);
    RUN_TEST(test_a_forced_open_entry_is_always_an_alert);
    RUN_TEST(test_entries_that_are_not_unlocks);
    RUN_TEST(test_lock_times_are_read_with_the_lock_offset);
    RUN_TEST(test_an_entry_time_that_cannot_exist_is_never_explained);
    return UNITY_END();
}
