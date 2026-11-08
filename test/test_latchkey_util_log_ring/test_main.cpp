// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>
#include <string>
#include <vector>

#include "latchkey_util/log_ring.h"

using latchkey_util::LogEntry;
using latchkey_util::LogLevel;
using latchkey_util::LogLine;
using latchkey_util::LogRing;

void setUp() {}

void tearDown() {}

static LogLine line(LogLevel level, std::string_view tag, std::string_view message) { return {level, tag, message}; }

static std::vector<uint32_t> readAll(const LogRing& ring, LogRing::Cursor cursor,
                                     LogLevel threshold = LogLevel::Verbose) {
    std::vector<uint32_t> seqs;
    LogEntry entry;
    while (ring.read(cursor, threshold, entry)) {
        seqs.push_back(entry.seq);
    }
    return seqs;
}

static void assertSeqs(const std::vector<uint32_t>& expected, const std::vector<uint32_t>& actual) {
    TEST_ASSERT_EQUAL_UINT32(expected.size(), actual.size());
    for (size_t i = 0; i < expected.size(); ++i) {
        TEST_ASSERT_EQUAL_UINT32(expected[i], actual[i]);
    }
}

static void test_a_prefixed_line_gives_level_tag_and_message() {
    const LogLine parsed = latchkey_util::parseLogLine("I (1234) wifi: connected, ip 192.0.2.62\n");
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(LogLevel::Info), static_cast<uint8_t>(parsed.level));
    TEST_ASSERT_EQUAL_STRING("wifi", std::string(parsed.tag).c_str());
    TEST_ASSERT_EQUAL_STRING("connected, ip 192.0.2.62", std::string(parsed.message).c_str());
}

static void test_every_level_letter_is_read() {
    const char* lines[] = {"E (1) t: m", "W (1) t: m", "I (1) t: m", "D (1) t: m", "V (1) t: m"};
    const LogLevel levels[] = {LogLevel::Error, LogLevel::Warn, LogLevel::Info, LogLevel::Debug, LogLevel::Verbose};
    for (size_t i = 0; i < 5; ++i) {
        TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(levels[i]),
                                static_cast<uint8_t>(latchkey_util::parseLogLine(lines[i]).level));
    }
}

static void test_an_unprefixed_line_is_info_without_a_tag() {
    const LogLine parsed = latchkey_util::parseLogLine("latchkey 0.2.0 board=esp32-devkit chip=esp32\r\n");
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(LogLevel::Info), static_cast<uint8_t>(parsed.level));
    TEST_ASSERT_TRUE(parsed.tag.empty());
    TEST_ASSERT_EQUAL_STRING("latchkey 0.2.0 board=esp32-devkit chip=esp32", std::string(parsed.message).c_str());
}

static void test_the_tag_ends_at_the_first_colon() {
    LogLine parsed = latchkey_util::parseLogLine("W (5) a: b: c");
    TEST_ASSERT_EQUAL_STRING("a", std::string(parsed.tag).c_str());
    TEST_ASSERT_EQUAL_STRING("b: c", std::string(parsed.message).c_str());
    parsed = latchkey_util::parseLogLine("I (77) wifi:mode : sta (00:00:5e:00:53:01)\n");
    TEST_ASSERT_EQUAL_STRING("wifi", std::string(parsed.tag).c_str());
    TEST_ASSERT_EQUAL_STRING("mode : sta (00:00:5e:00:53:01)", std::string(parsed.message).c_str());
    parsed = latchkey_util::parseLogLine("E (12) esp_netif_handlers_with_a_very_long_tag_name: x");
    TEST_ASSERT_EQUAL_STRING("esp_netif_handlers_with_a_very_long_tag_name", std::string(parsed.tag).c_str());
}

static void test_a_broken_prefix_keeps_the_whole_text() {
    const char* texts[] = {"X (1) t: m", "I (abc) t: m", "I(1) t: m", "I (1)t: m", "I (", ""};
    for (const char* text : texts) {
        const LogLine parsed = latchkey_util::parseLogLine(text);
        TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(LogLevel::Info), static_cast<uint8_t>(parsed.level));
        TEST_ASSERT_TRUE(parsed.tag.empty());
        TEST_ASSERT_EQUAL_STRING(text, std::string(parsed.message).c_str());
    }
}

static void test_a_prefix_without_a_tag_keeps_the_level() {
    const LogLine parsed = latchkey_util::parseLogLine("W (9) nothing to split here\n");
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(LogLevel::Warn), static_cast<uint8_t>(parsed.level));
    TEST_ASSERT_TRUE(parsed.tag.empty());
    TEST_ASSERT_EQUAL_STRING("nothing to split here", std::string(parsed.message).c_str());
}

static void test_level_names_round_trip() {
    const char* names[] = {"error", "warn", "info", "debug", "verbose"};
    for (const char* name : names) {
        const std::optional<LogLevel> level = latchkey_util::parseLogLevel(name);
        TEST_ASSERT_TRUE(level.has_value());
        TEST_ASSERT_EQUAL_STRING(name, std::string(latchkey_util::logLevelName(*level)).c_str());
    }
    TEST_ASSERT_FALSE(latchkey_util::parseLogLevel("none").has_value());
    TEST_ASSERT_FALSE(latchkey_util::parseLogLevel("INFO").has_value());
    TEST_ASSERT_FALSE(latchkey_util::parseLogLevel("").has_value());
}

static void test_a_threshold_passes_its_level_and_the_more_severe_ones() {
    TEST_ASSERT_TRUE(latchkey_util::passesLevel(LogLevel::Error, LogLevel::Warn));
    TEST_ASSERT_TRUE(latchkey_util::passesLevel(LogLevel::Warn, LogLevel::Warn));
    TEST_ASSERT_FALSE(latchkey_util::passesLevel(LogLevel::Info, LogLevel::Warn));
    TEST_ASSERT_TRUE(latchkey_util::passesLevel(LogLevel::Verbose, LogLevel::Verbose));
    TEST_ASSERT_FALSE(latchkey_util::passesLevel(LogLevel::Debug, LogLevel::Info));
}

static void test_a_cut_never_splits_a_utf8_sequence() {
    TEST_ASSERT_EQUAL_UINT32(5, latchkey_util::utf8Prefix("hello", 9));
    TEST_ASSERT_EQUAL_UINT32(3, latchkey_util::utf8Prefix("hello", 3));
    TEST_ASSERT_EQUAL_UINT32(1, latchkey_util::utf8Prefix("h\xc3\xa9llo", 2));
    TEST_ASSERT_EQUAL_UINT32(3, latchkey_util::utf8Prefix("h\xc3\xa9llo", 3));
    TEST_ASSERT_EQUAL_UINT32(1, latchkey_util::utf8Prefix("a\xe2\x82\xac", 3));
    TEST_ASSERT_EQUAL_UINT32(4, latchkey_util::utf8Prefix("a\xe2\x82\xac", 4));
}

static void test_the_ring_returns_what_was_appended() {
    uint8_t storage[512];
    LogRing ring(storage, sizeof(storage));
    TEST_ASSERT_EQUAL_UINT32(0, ring.count());
    TEST_ASSERT_EQUAL_UINT32(1, ring.append(1500, line(LogLevel::Warn, "wifi", "disconnected, reason 8")));
    TEST_ASSERT_EQUAL_UINT32(2, ring.append(1600, line(LogLevel::Info, "", "plain text")));
    LogRing::Cursor cursor = ring.oldestCursor();
    LogEntry entry;
    TEST_ASSERT_TRUE(ring.read(cursor, LogLevel::Verbose, entry));
    TEST_ASSERT_EQUAL_UINT32(1, entry.seq);
    TEST_ASSERT_EQUAL_UINT32(1500, entry.upMs);
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(LogLevel::Warn), static_cast<uint8_t>(entry.level));
    TEST_ASSERT_EQUAL_STRING("wifi", std::string(entry.tagText()).c_str());
    TEST_ASSERT_EQUAL_STRING("disconnected, reason 8", std::string(entry.messageText()).c_str());
    TEST_ASSERT_TRUE(ring.read(cursor, LogLevel::Verbose, entry));
    TEST_ASSERT_EQUAL_UINT32(2, entry.seq);
    TEST_ASSERT_TRUE(entry.tagText().empty());
    TEST_ASSERT_EQUAL_STRING("plain text", std::string(entry.messageText()).c_str());
    TEST_ASSERT_FALSE(ring.read(cursor, LogLevel::Verbose, entry));
    TEST_ASSERT_EQUAL_UINT32(2, ring.count());
    TEST_ASSERT_EQUAL_UINT32(1, ring.oldest());
    TEST_ASSERT_EQUAL_UINT32(3, ring.next());
}

static void test_a_full_ring_drops_the_oldest_lines_first() {
    uint8_t storage[300];
    LogRing ring(storage, sizeof(storage));
    const std::string message(40, 'm');
    for (uint32_t i = 1; i <= 20; ++i) {
        TEST_ASSERT_EQUAL_UINT32(i, ring.append(i, line(LogLevel::Info, "tag", message)));
        TEST_ASSERT_TRUE(ring.usedBytes() <= sizeof(storage));
    }
    const size_t held = ring.count();
    TEST_ASSERT_TRUE(held >= 4 && held < 20);
    TEST_ASSERT_EQUAL_UINT32(21 - held, ring.oldest());
    std::vector<uint32_t> expected;
    for (uint32_t seq = 21 - held; seq <= 20; ++seq) {
        expected.push_back(seq);
    }
    assertSeqs(expected, readAll(ring, ring.oldestCursor()));
    LogRing::Cursor cursor = ring.after(19);
    LogEntry entry;
    TEST_ASSERT_TRUE(ring.read(cursor, LogLevel::Verbose, entry));
    TEST_ASSERT_EQUAL_UINT32(20, entry.seq);
    TEST_ASSERT_EQUAL_STRING(message.c_str(), std::string(entry.messageText()).c_str());
}

static void test_lines_survive_the_wrap_of_the_storage_intact() {
    uint8_t storage[257];
    LogRing ring(storage, sizeof(storage));
    for (uint32_t i = 1; i <= 200; ++i) {
        const std::string message = "line " + std::to_string(i) + std::string(i % 37, 'x');
        ring.append(i * 10, line(i % 2 == 0 ? LogLevel::Warn : LogLevel::Info, "t" + std::to_string(i % 7), message));
        LogRing::Cursor cursor = ring.oldestCursor();
        LogEntry entry;
        uint32_t expected = ring.oldest();
        while (ring.read(cursor, LogLevel::Verbose, entry)) {
            const std::string text = "line " + std::to_string(entry.seq) + std::string(entry.seq % 37, 'x');
            TEST_ASSERT_EQUAL_UINT32(expected, entry.seq);
            TEST_ASSERT_EQUAL_UINT32(entry.seq * 10, entry.upMs);
            TEST_ASSERT_EQUAL_STRING(text.c_str(), std::string(entry.messageText()).c_str());
            TEST_ASSERT_EQUAL_STRING(("t" + std::to_string(entry.seq % 7)).c_str(),
                                     std::string(entry.tagText()).c_str());
            ++expected;
        }
        TEST_ASSERT_EQUAL_UINT32(i + 1, expected);
    }
}

static void test_a_cursor_behind_the_oldest_line_jumps_to_it() {
    uint8_t storage[300];
    LogRing ring(storage, sizeof(storage));
    ring.append(1, line(LogLevel::Info, "a", "first"));
    LogRing::Cursor stale = ring.oldestCursor();
    const std::string message(60, 'z');
    for (uint32_t i = 0; i < 12; ++i) {
        ring.append(2 + i, line(LogLevel::Info, "b", message));
    }
    TEST_ASSERT_TRUE(ring.oldest() > 1);
    LogEntry entry;
    TEST_ASSERT_TRUE(ring.read(stale, LogLevel::Verbose, entry));
    TEST_ASSERT_EQUAL_UINT32(ring.oldest(), entry.seq);
    TEST_ASSERT_EQUAL_UINT32(ring.oldest(), ring.after(0).seq);
}

static void test_a_cursor_at_the_end_sees_lines_appended_later() {
    uint8_t storage[400];
    LogRing ring(storage, sizeof(storage));
    ring.append(1, line(LogLevel::Info, "a", "one"));
    LogRing::Cursor cursor = ring.after(1);
    LogEntry entry;
    TEST_ASSERT_FALSE(ring.read(cursor, LogLevel::Verbose, entry));
    ring.append(2, line(LogLevel::Info, "a", "two"));
    TEST_ASSERT_TRUE(ring.read(cursor, LogLevel::Verbose, entry));
    TEST_ASSERT_EQUAL_UINT32(2, entry.seq);
    TEST_ASSERT_EQUAL_STRING("two", std::string(entry.messageText()).c_str());
    TEST_ASSERT_EQUAL_UINT32(ring.next(), ring.after(99).seq);
}

static void test_reading_with_a_threshold_skips_the_less_severe_lines() {
    uint8_t storage[1024];
    LogRing ring(storage, sizeof(storage));
    const LogLevel levels[] = {LogLevel::Info, LogLevel::Error, LogLevel::Debug, LogLevel::Warn, LogLevel::Info};
    for (LogLevel level : levels) {
        ring.append(0, line(level, "t", "m"));
    }
    assertSeqs({2, 4}, readAll(ring, ring.oldestCursor(), LogLevel::Warn));
    assertSeqs({1, 2, 4, 5}, readAll(ring, ring.oldestCursor(), LogLevel::Info));
    assertSeqs({2}, readAll(ring, ring.oldestCursor(), LogLevel::Error));
    assertSeqs({1, 2, 3, 4, 5}, readAll(ring, ring.oldestCursor(), LogLevel::Verbose));
}

static void test_the_newest_window_holds_the_last_matching_lines() {
    uint8_t storage[1024];
    LogRing ring(storage, sizeof(storage));
    const LogLevel levels[] = {LogLevel::Warn, LogLevel::Info, LogLevel::Warn, LogLevel::Info, LogLevel::Error};
    for (LogLevel level : levels) {
        ring.append(0, line(level, "t", "m"));
    }
    assertSeqs({4, 5}, readAll(ring, ring.newest(2, LogLevel::Verbose)));
    assertSeqs({3, 5}, readAll(ring, ring.newest(2, LogLevel::Warn), LogLevel::Warn));
    assertSeqs({1, 3, 5}, readAll(ring, ring.newest(10, LogLevel::Warn), LogLevel::Warn));
    assertSeqs({}, readAll(ring, ring.newest(0, LogLevel::Verbose)));
}

static void test_control_characters_become_spaces_and_long_text_is_cut() {
    uint8_t storage[1024];
    LogRing ring(storage, sizeof(storage));
    ring.append(0, line(LogLevel::Info, "t\x01g", "a\tb\x1b" "c\x7f"));
    const std::string longTag(40, 'g');
    std::string longMessage(latchkey_util::kMaxLogMessage - 1, 'm');
    longMessage += "\xc3\xa9tail";
    ring.append(0, line(LogLevel::Info, longTag, longMessage));
    LogRing::Cursor cursor = ring.oldestCursor();
    LogEntry entry;
    TEST_ASSERT_TRUE(ring.read(cursor, LogLevel::Verbose, entry));
    TEST_ASSERT_EQUAL_STRING("t g", std::string(entry.tagText()).c_str());
    TEST_ASSERT_EQUAL_STRING("a b c ", std::string(entry.messageText()).c_str());
    TEST_ASSERT_TRUE(ring.read(cursor, LogLevel::Verbose, entry));
    TEST_ASSERT_EQUAL_UINT32(latchkey_util::kMaxLogTag, entry.tagText().size());
    TEST_ASSERT_EQUAL_UINT32(latchkey_util::kMaxLogMessage - 1, entry.messageText().size());
    TEST_ASSERT_EQUAL_STRING(std::string(latchkey_util::kMaxLogMessage - 1, 'm').c_str(),
                             std::string(entry.messageText()).c_str());
}

static void test_text_reaches_the_ring_unchanged() {
    uint8_t storage[1024];
    LogRing ring(storage, sizeof(storage));
    const char* message = "HTTPS certificate SHA-256 AB:CD:EF:01:23:45 caf\xc3\xa9 [x] \"q\" \\ / {}";
    ring.append(7, line(LogLevel::Error, "certs", message));
    LogRing::Cursor cursor = ring.oldestCursor();
    LogEntry entry;
    TEST_ASSERT_TRUE(ring.read(cursor, LogLevel::Verbose, entry));
    TEST_ASSERT_EQUAL_STRING(message, std::string(entry.messageText()).c_str());
}

static void test_a_line_bigger_than_a_tiny_ring_still_fits() {
    uint8_t storage[64];
    LogRing ring(storage, sizeof(storage));
    ring.append(0, line(LogLevel::Info, "tag", std::string(200, 'm')));
    ring.append(0, line(LogLevel::Info, "tag", std::string(200, 'n')));
    TEST_ASSERT_EQUAL_UINT32(1, ring.count());
    TEST_ASSERT_TRUE(ring.usedBytes() <= sizeof(storage));
    LogRing::Cursor cursor = ring.oldestCursor();
    LogEntry entry;
    TEST_ASSERT_TRUE(ring.read(cursor, LogLevel::Verbose, entry));
    TEST_ASSERT_EQUAL_UINT32(2, entry.seq);
    TEST_ASSERT_TRUE(entry.messageText().size() > 0);
    TEST_ASSERT_EQUAL_CHAR('n', entry.messageText()[0]);
}

static void test_times_come_from_the_age_of_a_line() {
    latchkey_util::LogTimes times = latchkey_util::logTimes(1000, 5000, std::optional<int64_t>(1794146587512));
    TEST_ASSERT_EQUAL_UINT64(1000, times.uptimeMs);
    TEST_ASSERT_TRUE(times.utcMs.has_value());
    TEST_ASSERT_EQUAL_INT64(1794146583512, *times.utcMs);
    times = latchkey_util::logTimes(1000, 5000, std::nullopt);
    TEST_ASSERT_FALSE(times.utcMs.has_value());
    const uint64_t now = (uint64_t{1} << 32) + 500;
    times = latchkey_util::logTimes(0xFFFFFF00u, now, std::nullopt);
    TEST_ASSERT_EQUAL_UINT64(now - (500 + 0x100), times.uptimeMs);
}

static void test_an_entry_renders_as_one_json_object() {
    uint8_t storage[512];
    LogRing ring(storage, sizeof(storage));
    ring.append(1500, line(LogLevel::Warn, "wifi", "say \"hi\" \\ now"));
    LogRing::Cursor cursor = ring.oldestCursor();
    LogEntry entry;
    TEST_ASSERT_TRUE(ring.read(cursor, LogLevel::Verbose, entry));
    std::string out;
    latchkey_util::appendLogEntryJson(out, entry, {1500, std::optional<int64_t>(1794146587512)});
    TEST_ASSERT_EQUAL_STRING(
        "{\"seq\":1,\"uptimeMs\":1500,\"utcMs\":1794146587512,\"level\":\"warn\",\"tag\":\"wifi\","
        "\"message\":\"say \\\"hi\\\" \\\\ now\"}",
        out.c_str());
    out.clear();
    latchkey_util::appendLogEntryJson(out, entry, {1500, std::nullopt});
    TEST_ASSERT_EQUAL_STRING(
        "{\"seq\":1,\"uptimeMs\":1500,\"utcMs\":null,\"level\":\"warn\",\"tag\":\"wifi\","
        "\"message\":\"say \\\"hi\\\" \\\\ now\"}",
        out.c_str());
}

struct Joined {
    std::vector<std::string> lines;
    latchkey_util::LogJoiner joiner;

    void feed(uintptr_t writer, std::string_view piece) {
        const bool ends = !piece.empty() && piece.back() == '\n';
        joiner.feed(writer, piece, ends, [this](std::string_view line) { lines.emplace_back(line); });
    }

    void feedCut(uintptr_t writer, std::string_view piece) {
        joiner.feed(writer, piece, true, [this](std::string_view line) { lines.emplace_back(line); });
    }
};

static void test_a_whole_line_passes_at_once() {
    Joined joined;
    joined.feed(1, "I (5) wifi: connected\n");
    TEST_ASSERT_EQUAL_UINT32(1, joined.lines.size());
    TEST_ASSERT_EQUAL_STRING("I (5) wifi: connected\n", joined.lines[0].c_str());
}

static void test_pieces_of_one_writer_become_one_line() {
    Joined joined;
    joined.feed(7, "I (551) wifi:");
    joined.feed(7, "mode : sta (00:00:5e:00:53:01)");
    TEST_ASSERT_EQUAL_UINT32(0, joined.lines.size());
    joined.feed(7, "\n");
    TEST_ASSERT_EQUAL_UINT32(1, joined.lines.size());
    TEST_ASSERT_EQUAL_STRING("I (551) wifi:mode : sta (00:00:5e:00:53:01)\n", joined.lines[0].c_str());
    const LogLine parsed = latchkey_util::parseLogLine(joined.lines[0]);
    TEST_ASSERT_EQUAL_STRING("wifi", std::string(parsed.tag).c_str());
    TEST_ASSERT_EQUAL_STRING("mode : sta (00:00:5e:00:53:01)", std::string(parsed.message).c_str());
}

static void test_empty_lines_are_dropped() {
    Joined joined;
    joined.feed(1, "\n");
    joined.feed(1, "\r\n");
    joined.feed(1, "");
    TEST_ASSERT_EQUAL_UINT32(0, joined.lines.size());
}

static void test_another_writer_keeps_its_own_lines() {
    Joined joined;
    joined.feed(1, "I (1) wifi:");
    joined.feed(2, "W (2) http: busy\n");
    TEST_ASSERT_EQUAL_UINT32(1, joined.lines.size());
    TEST_ASSERT_EQUAL_STRING("W (2) http: busy\n", joined.lines[0].c_str());
    joined.feed(1, "flush txq\n");
    TEST_ASSERT_EQUAL_UINT32(2, joined.lines.size());
    TEST_ASSERT_EQUAL_STRING("I (1) wifi:flush txq\n", joined.lines[1].c_str());
}

static void test_a_new_piece_from_another_writer_closes_the_open_line() {
    Joined joined;
    joined.feed(1, "I (1) wifi:");
    joined.feed(2, "I (2) a:");
    TEST_ASSERT_EQUAL_UINT32(1, joined.lines.size());
    TEST_ASSERT_EQUAL_STRING("I (1) wifi:", joined.lines[0].c_str());
    joined.feed(2, " b\n");
    TEST_ASSERT_EQUAL_UINT32(2, joined.lines.size());
    TEST_ASSERT_EQUAL_STRING("I (2) a: b\n", joined.lines[1].c_str());
}

static void test_an_overlong_line_is_cut() {
    Joined joined;
    const std::string piece(200, 'x');
    joined.feed(1, piece);
    joined.feed(1, piece);
    joined.feed(1, "\n");
    TEST_ASSERT_EQUAL_UINT32(1, joined.lines.size());
    TEST_ASSERT_EQUAL_UINT32(latchkey_util::LogJoiner::kCapacity, joined.lines[0].size());
}

static void test_a_line_the_console_cut_does_not_swallow_the_next_one() {
    Joined joined;
    const std::string cut = "I (9) http: " + std::string(243, 'c');
    joined.feedCut(1, cut);
    joined.feed(1, "I (10) a: next\n");
    TEST_ASSERT_EQUAL_UINT32(2, joined.lines.size());
    TEST_ASSERT_EQUAL_STRING(cut.c_str(), joined.lines[0].c_str());
    TEST_ASSERT_EQUAL_STRING("I (10) a: next\n", joined.lines[1].c_str());
}

static void test_a_cut_line_ends_the_pieces_before_it() {
    Joined joined;
    joined.feed(1, "I (11) wifi:");
    joined.feedCut(1, std::string(250, 'w'));
    joined.feed(1, "I (12) b: after\n");
    TEST_ASSERT_EQUAL_UINT32(2, joined.lines.size());
    TEST_ASSERT_EQUAL_UINT32(latchkey_util::LogJoiner::kCapacity, joined.lines[0].size());
    TEST_ASSERT_EQUAL_STRING("I (12) b: after\n", joined.lines[1].c_str());
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_a_line_the_console_cut_does_not_swallow_the_next_one);
    RUN_TEST(test_a_cut_line_ends_the_pieces_before_it);
    RUN_TEST(test_a_whole_line_passes_at_once);
    RUN_TEST(test_pieces_of_one_writer_become_one_line);
    RUN_TEST(test_empty_lines_are_dropped);
    RUN_TEST(test_another_writer_keeps_its_own_lines);
    RUN_TEST(test_a_new_piece_from_another_writer_closes_the_open_line);
    RUN_TEST(test_an_overlong_line_is_cut);
    RUN_TEST(test_a_prefixed_line_gives_level_tag_and_message);
    RUN_TEST(test_every_level_letter_is_read);
    RUN_TEST(test_an_unprefixed_line_is_info_without_a_tag);
    RUN_TEST(test_the_tag_ends_at_the_first_colon);
    RUN_TEST(test_a_broken_prefix_keeps_the_whole_text);
    RUN_TEST(test_a_prefix_without_a_tag_keeps_the_level);
    RUN_TEST(test_level_names_round_trip);
    RUN_TEST(test_a_threshold_passes_its_level_and_the_more_severe_ones);
    RUN_TEST(test_a_cut_never_splits_a_utf8_sequence);
    RUN_TEST(test_the_ring_returns_what_was_appended);
    RUN_TEST(test_a_full_ring_drops_the_oldest_lines_first);
    RUN_TEST(test_lines_survive_the_wrap_of_the_storage_intact);
    RUN_TEST(test_a_cursor_behind_the_oldest_line_jumps_to_it);
    RUN_TEST(test_a_cursor_at_the_end_sees_lines_appended_later);
    RUN_TEST(test_reading_with_a_threshold_skips_the_less_severe_lines);
    RUN_TEST(test_the_newest_window_holds_the_last_matching_lines);
    RUN_TEST(test_control_characters_become_spaces_and_long_text_is_cut);
    RUN_TEST(test_text_reaches_the_ring_unchanged);
    RUN_TEST(test_a_line_bigger_than_a_tiny_ring_still_fits);
    RUN_TEST(test_times_come_from_the_age_of_a_line);
    RUN_TEST(test_an_entry_renders_as_one_json_object);
    return UNITY_END();
}
