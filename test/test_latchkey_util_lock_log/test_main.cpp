// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>
#include <functional>
#include <set>
#include <string>
#include <vector>

#include "latchkey_util/lock_log.h"
#include "latchkey_util/lock_watch.h"
#include "ttlock/commands.h"
#include "ttlock/types.h"

using latchkey_util::LogEndSearch;
using latchkey_util::LogStep;
using latchkey_util::WatchState;
using ttlock::LockTime;
using ttlock::LogEntry;
using ttlock::LogPage;

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

static constexpr int64_t kNoon = 1762516800;

static LockTime localTime(int64_t utc, int32_t offset) {
    const int64_t local = utc + offset;
    const int64_t days = local / 86400;
    const int64_t second = local % 86400;
    int64_t z = days + 719468;
    const int64_t era = z / 146097;
    const int64_t doe = z - era * 146097;
    const int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const int64_t mp = (5 * doy + 2) / 153;
    const int64_t day = doy - (153 * mp + 2) / 5 + 1;
    const int64_t month = mp < 10 ? mp + 3 : mp - 9;
    const int64_t year = yoe + era * 400 + (month <= 2 ? 1 : 0);
    return LockTime{static_cast<uint16_t>(year), static_cast<uint8_t>(month), static_cast<uint8_t>(day),
                    static_cast<uint8_t>(second / 3600), static_cast<uint8_t>(second % 3600 / 60),
                    static_cast<uint8_t>(second % 60)};
}

static LogPage page(uint16_t sequence, std::vector<LogEntry> entries) {
    LogPage out;
    out.sequence = sequence;
    out.entries = std::move(entries);
    return out;
}

static LogEntry recorded(uint16_t seq, uint8_t type, int64_t utc) {
    return entry(seq, type, localTime(utc, kOffset), 80);
}

static WatchState watching(uint16_t cursor, int64_t lastUtc) {
    WatchState state;
    state.baselined = true;
    state.cursor = cursor;
    state.lastUtc = static_cast<uint32_t>(lastUtc);
    return state;
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

static void test_a_record_at_the_cursor_is_new_and_moves_the_cursor_on() {
    const WatchState before = watching(154, kNoon);
    const LogStep step = latchkey_util::stepLog(before, page(155, {recorded(154, 1, kNoon + 60)}), kOffset);
    TEST_ASSERT_EQUAL_UINT(1, step.fresh.size());
    TEST_ASSERT_EQUAL_UINT(0, step.fresh[0]);
    TEST_ASSERT_TRUE(step.more);
    TEST_ASSERT_EQUAL_UINT16(155, step.state.cursor);
    TEST_ASSERT_EQUAL_UINT32(kNoon + 60, step.state.lastUtc);
    TEST_ASSERT_TRUE(step.state.baselined);
}

static void test_a_record_over_two_slots_moves_the_cursor_past_both() {
    const LogStep step = latchkey_util::stepLog(watching(100, kNoon), page(102, {recorded(101, 93, kNoon + 5)}), kOffset);
    TEST_ASSERT_EQUAL_UINT(1, step.fresh.size());
    TEST_ASSERT_EQUAL_UINT16(102, step.state.cursor);
}

static void test_the_end_of_the_log_is_an_empty_page_or_an_older_record() {
    const WatchState before = watching(170, kNoon);
    for (const LogPage& end : {page(0, {}), page(1, {recorded(0, 1, kNoon - 86400)}),
                               page(166, {recorded(165, 26, kNoon)})}) {
        const LogStep step = latchkey_util::stepLog(before, end, kOffset);
        TEST_ASSERT_EQUAL_UINT(0, step.fresh.size());
        TEST_ASSERT_FALSE(step.more);
        TEST_ASSERT_TRUE(step.state == before);
    }
}

static void test_a_newer_record_below_the_cursor_means_the_log_started_over() {
    const LogStep step =
        latchkey_util::stepLog(watching(2000, kNoon), page(1, {recorded(0, 1, kNoon + 60)}), kOffset);
    TEST_ASSERT_EQUAL_UINT(1, step.fresh.size());
    TEST_ASSERT_EQUAL_UINT16(1, step.state.cursor);
    TEST_ASSERT_EQUAL_UINT32(kNoon + 60, step.state.lastUtc);
    TEST_ASSERT_TRUE(step.more);
}

static void test_a_record_with_an_impossible_time_never_restarts_the_log() {
    const LogEntry broken = entry(0, 1, LockTime{2025, 13, 1, 0, 0, 0}, 80);
    const LogStep below = latchkey_util::stepLog(watching(2000, kNoon), page(1, {broken}), kOffset);
    TEST_ASSERT_EQUAL_UINT(0, below.fresh.size());
    const LogStep at = latchkey_util::stepLog(watching(0, kNoon), page(1, {broken}), kOffset);
    TEST_ASSERT_EQUAL_UINT(1, at.fresh.size());
    TEST_ASSERT_EQUAL_UINT32(kNoon, at.state.lastUtc);
}

enum class PastTheEnd { FirstRecord, EmptyPage, LastRead };

struct FakeLog {
    uint16_t records = 0;
    std::set<uint16_t> secondSlots;
    PastTheEnd pastTheEnd = PastTheEnd::FirstRecord;
    uint16_t lastRead = 0;

    LogPage read(uint16_t slot) {
        if (slot >= records) {
            switch (pastTheEnd) {
                case PastTheEnd::FirstRecord:
                    return records == 0 ? page(0, {}) : at(0);
                case PastTheEnd::EmptyPage:
                    return page(0, {});
                case PastTheEnd::LastRead:
                    return records == 0 ? page(0, {}) : at(lastRead);
            }
        }
        lastRead = slot;
        return at(slot);
    }

    LogPage at(uint16_t slot) const {
        const uint16_t seq = secondSlots.count(static_cast<uint16_t>(slot + 1)) > 0 ? slot + 1 : slot;
        return page(static_cast<uint16_t>(seq + 1), {recorded(seq, 1, kNoon + seq)});
    }
};

static WatchState searchEnd(FakeLog& log, size_t& reads) {
    LogEndSearch search;
    while (!search.done()) {
        search.read(log.read(search.slot()), kOffset);
    }
    reads = search.reads();
    return search.baseline(WatchState{});
}

static void test_the_end_search_finds_the_slot_after_the_newest_record() {
    for (const PastTheEnd mode : {PastTheEnd::FirstRecord, PastTheEnd::EmptyPage, PastTheEnd::LastRead}) {
        FakeLog log{166, {9, 13, 29, 101, 165}, mode};
        size_t reads = 0;
        const WatchState found = searchEnd(log, reads);
        TEST_ASSERT_TRUE(found.baselined);
        TEST_ASSERT_EQUAL_UINT16(166, found.cursor);
        TEST_ASSERT_EQUAL_UINT32(kNoon + 165, found.lastUtc);
        TEST_ASSERT_LESS_OR_EQUAL_UINT(17, reads);
    }
}

static void test_the_end_search_on_short_and_empty_logs() {
    FakeLog one{1, {}, PastTheEnd::EmptyPage};
    size_t reads = 0;
    WatchState found = searchEnd(one, reads);
    TEST_ASSERT_EQUAL_UINT16(1, found.cursor);
    TEST_ASSERT_EQUAL_UINT32(kNoon, found.lastUtc);
    FakeLog none{0, {}, PastTheEnd::FirstRecord};
    found = searchEnd(none, reads);
    TEST_ASSERT_TRUE(found.baselined);
    TEST_ASSERT_EQUAL_UINT16(0, found.cursor);
    TEST_ASSERT_EQUAL_UINT32(0, found.lastUtc);
    TEST_ASSERT_LESS_OR_EQUAL_UINT(17, reads);
}

static void test_the_end_search_keeps_the_clock_part_of_the_state() {
    FakeLog log{40, {}, PastTheEnd::FirstRecord};
    WatchState clock;
    clock.clockKnown = true;
    clock.clockOffset = kOffset;
    clock.clockSetUtc = 12345;
    LogEndSearch search;
    while (!search.done()) {
        search.read(log.read(search.slot()), kOffset);
    }
    const WatchState found = search.baseline(clock);
    TEST_ASSERT_TRUE(found.clockKnown);
    TEST_ASSERT_EQUAL_INT32(kOffset, found.clockOffset);
    TEST_ASSERT_EQUAL_UINT32(12345, found.clockSetUtc);
    TEST_ASSERT_EQUAL_UINT16(40, found.cursor);
}

static void test_an_undated_tail_preserves_the_known_baseline_and_does_not_replay_old_records() {
    FakeLog log{166, {}, PastTheEnd::FirstRecord};
    LogEndSearch search;
    while (!search.done()) {
        auto returned = log.read(search.slot());
        for (auto& item : returned.entries) {
            if (item.recordNumber == 165) item.time = LockTime{2025, 0, 0, 0, 0, 0};
        }
        search.read(returned, kOffset);
    }
    const WatchState found = search.baseline({});
    TEST_ASSERT_EQUAL_UINT16(166, found.cursor);
    TEST_ASSERT_GREATER_OR_EQUAL_UINT32(kNoon, found.lastUtc);
    const LogStep repeated = latchkey_util::stepLog(found, page(1, {recorded(0, 1, kNoon)}), kOffset);
    TEST_ASSERT_TRUE(repeated.fresh.empty());
    TEST_ASSERT_TRUE(repeated.state == found);
}

static void test_an_entirely_undated_baseline_cannot_prove_a_log_restart() {
    const WatchState before = watching(166, 0);
    const LogStep repeated = latchkey_util::stepLog(before, page(1, {recorded(0, 1, kNoon)}), kOffset);
    TEST_ASSERT_TRUE(repeated.fresh.empty());
    TEST_ASSERT_TRUE(repeated.state == before);
    const LogStep next = latchkey_util::stepLog(before, page(167, {recorded(166, 1, kNoon + 60)}), kOffset);
    TEST_ASSERT_EQUAL_UINT(1, next.fresh.size());
    TEST_ASSERT_EQUAL_UINT32(kNoon + 60, next.state.lastUtc);
}

static void test_end_search_keeps_the_maximum_date_seen_in_a_mixed_page() {
    LogEndSearch search;
    const uint16_t asked = search.slot();
    const auto undated = entry(asked + 1, 1, LockTime{2025, 0, 0, 0, 0, 0}, 80);
    search.read(page(asked + 2, {recorded(asked, 1, kNoon), undated}), kOffset);
    TEST_ASSERT_EQUAL_UINT32(kNoon, search.baseline({}).lastUtc);
}

static void test_history_keeps_each_records_offset_across_a_clock_change() {
    WatchState state = watching(12, kNoon + 60);
    latchkey_util::clockSet(state, kOffset, kNoon);
    state.cursor = 13;
    latchkey_util::clockSet(state, kOffset - 3600, kNoon + 30);
    const std::vector<LogEntry> entries{
        recorded(12, 1, kNoon + 5),
        entry(13, 1, localTime(kNoon + 35, kOffset - 3600), 79)};
    TEST_ASSERT_EQUAL_STRING(R"([{"seq":12,"time":1762516805,"type":1,"battery":80},)"
                             R"({"seq":13,"time":1762516835,"type":1,"battery":79}])",
                             latchkey_util::logEntriesJson(entries, state, 0).c_str());
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_log_entries_render_without_their_credentials);
    RUN_TEST(test_times_are_utc_through_the_offset_the_lock_clock_was_set_with);
    RUN_TEST(test_history_keeps_each_records_offset_across_a_clock_change);
    RUN_TEST(test_an_entry_time_that_cannot_exist_renders_as_null);
    RUN_TEST(test_an_empty_page_renders_as_an_empty_list);
    RUN_TEST(test_a_record_at_the_cursor_is_new_and_moves_the_cursor_on);
    RUN_TEST(test_a_record_over_two_slots_moves_the_cursor_past_both);
    RUN_TEST(test_the_end_of_the_log_is_an_empty_page_or_an_older_record);
    RUN_TEST(test_a_newer_record_below_the_cursor_means_the_log_started_over);
    RUN_TEST(test_a_record_with_an_impossible_time_never_restarts_the_log);
    RUN_TEST(test_the_end_search_finds_the_slot_after_the_newest_record);
    RUN_TEST(test_the_end_search_on_short_and_empty_logs);
    RUN_TEST(test_the_end_search_keeps_the_clock_part_of_the_state);
    RUN_TEST(test_an_undated_tail_preserves_the_known_baseline_and_does_not_replay_old_records);
    RUN_TEST(test_an_entirely_undated_baseline_cannot_prove_a_log_restart);
    RUN_TEST(test_end_search_keeps_the_maximum_date_seen_in_a_mixed_page);
    return UNITY_END();
}
