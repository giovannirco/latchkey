// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <string>
#include <vector>

#include "latchkey_util/lock_log.h"
#include "ttlock/types.h"

using ttlock::LockTime;
using ttlock::LogEntry;

void setUp() {}

void tearDown() {}

static constexpr int32_t kOffset = -3 * 3600;

static LogEntry entry(uint16_t seq, uint8_t type, const LockTime& time, uint8_t battery) {
    LogEntry log;
    log.recordNumber = seq;
    log.type = type;
    log.time = time;
    log.battery = battery;
    return log;
}

static void test_log_entries_render_without_their_credentials() {
    LogEntry passcode = entry(12, 4, LockTime{2025, 11, 7, 11, 0, 0}, 57);
    passcode.credential = "3141592";
    passcode.newCredential = "2718281";
    passcode.uid = 77;
    passcode.recordId = 88;
    const std::string text = latchkey_util::logEntriesJson({passcode}, kOffset);
    TEST_ASSERT_EQUAL_STRING(R"([{"seq":12,"time":1762524000,"type":4,"battery":57}])", text.c_str());
    TEST_ASSERT_EQUAL(std::string::npos, text.find("3141592"));
    TEST_ASSERT_EQUAL(std::string::npos, text.find("2718281"));
}

static void test_times_are_utc_through_the_offset_the_lock_clock_was_set_with() {
    const std::vector<LogEntry> entries{entry(1, 14, LockTime{2026, 1, 1, 0, 0, 5}, 100),
                                        entry(2, 26, LockTime{2026, 1, 1, 0, 0, 5}, 99)};
    TEST_ASSERT_EQUAL_STRING(R"([{"seq":1,"time":1767225605,"type":14,"battery":100},)"
                             R"({"seq":2,"time":1767225605,"type":26,"battery":99}])",
                             latchkey_util::logEntriesJson(entries, 0).c_str());
    TEST_ASSERT_EQUAL_STRING(R"([{"seq":1,"time":1767236405,"type":14,"battery":100},)"
                             R"({"seq":2,"time":1767236405,"type":26,"battery":99}])",
                             latchkey_util::logEntriesJson(entries, kOffset).c_str());
}

static void test_an_entry_time_that_cannot_exist_renders_as_null() {
    const std::vector<LogEntry> entries{entry(5, 1, LockTime{2025, 2, 29, 10, 0, 0}, 50),
                                        entry(6, 1, LockTime{2025, 13, 1, 10, 0, 0}, 50)};
    TEST_ASSERT_EQUAL_STRING(R"([{"seq":5,"time":null,"type":1,"battery":50},)"
                             R"({"seq":6,"time":null,"type":1,"battery":50}])",
                             latchkey_util::logEntriesJson(entries, kOffset).c_str());
}

static void test_an_empty_page_renders_as_an_empty_list() {
    TEST_ASSERT_EQUAL_STRING("[]", latchkey_util::logEntriesJson({}, kOffset).c_str());
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_log_entries_render_without_their_credentials);
    RUN_TEST(test_times_are_utc_through_the_offset_the_lock_clock_was_set_with);
    RUN_TEST(test_an_entry_time_that_cannot_exist_renders_as_null);
    RUN_TEST(test_an_empty_page_renders_as_an_empty_list);
    return UNITY_END();
}
