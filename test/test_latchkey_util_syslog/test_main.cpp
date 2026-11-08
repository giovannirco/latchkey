// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>
#include <cstring>
#include <string>

#include "latchkey_util/syslog.h"

using latchkey_util::LogLevel;
using latchkey_util::SyslogMessage;

void setUp() {}

void tearDown() {}

static SyslogMessage message(std::string_view text, std::optional<int64_t> utcMs = std::nullopt) {
    SyslogMessage out;
    out.level = LogLevel::Info;
    out.seq = 4812;
    out.uptimeMs = 1304120;
    out.utcMs = utcMs;
    out.hostname = "esp32s3-atom";
    out.appName = "latchkey";
    out.tag = "wifi";
    out.message = text;
    return out;
}

static std::string format(const SyslogMessage& input, size_t maxBytes = 1024) {
    std::string out = "stale";
    latchkey_util::formatSyslog(out, input, maxBytes);
    return out;
}

static void test_each_level_maps_to_a_syslog_severity() {
    TEST_ASSERT_EQUAL_UINT8(3, latchkey_util::syslogSeverity(LogLevel::Error));
    TEST_ASSERT_EQUAL_UINT8(4, latchkey_util::syslogSeverity(LogLevel::Warn));
    TEST_ASSERT_EQUAL_UINT8(6, latchkey_util::syslogSeverity(LogLevel::Info));
    TEST_ASSERT_EQUAL_UINT8(7, latchkey_util::syslogSeverity(LogLevel::Debug));
    TEST_ASSERT_EQUAL_UINT8(7, latchkey_util::syslogSeverity(LogLevel::Verbose));
}

static void test_a_synced_line_carries_every_rfc5424_field() {
    TEST_ASSERT_EQUAL_STRING(
        "<134>1 2026-11-08T14:03:07.512Z esp32s3-atom latchkey - wifi "
        "[meta sequenceId=\"4812\" sysUpTime=\"130412\"] connected, ip 192.0.2.62",
        format(message("connected, ip 192.0.2.62", 1794146587512)).c_str());
}

static void test_an_unsynced_line_has_no_timestamp() {
    TEST_ASSERT_EQUAL_STRING(
        "<134>1 - esp32s3-atom latchkey - wifi [meta sequenceId=\"4812\" sysUpTime=\"130412\"] SNTP not synced",
        format(message("SNTP not synced")).c_str());
}

static void test_the_priority_uses_facility_local0() {
    SyslogMessage input = message("x");
    input.level = LogLevel::Error;
    TEST_ASSERT_EQUAL_STRING("<131>", format(input).substr(0, 5).c_str());
    input.level = LogLevel::Debug;
    TEST_ASSERT_EQUAL_STRING("<135>", format(input).substr(0, 5).c_str());
}

static void test_timestamps_keep_milliseconds_and_pad_every_field() {
    TEST_ASSERT_EQUAL_STRING("<134>1 2024-01-01T00:00:00.007Z",
                             format(message("x", 1704067200007)).substr(0, 31).c_str());
    TEST_ASSERT_EQUAL_STRING("<134>1 2099-12-31T23:59:59.999Z",
                             format(message("x", 4102444799999)).substr(0, 31).c_str());
}

static void test_header_fields_hold_only_printable_ascii() {
    SyslogMessage input = message("m");
    input.tag = "a tag\xc3\xa9";
    input.hostname = "board one";
    TEST_ASSERT_EQUAL_STRING(
        "<134>1 - board_one latchkey - a_tag__ [meta sequenceId=\"4812\" sysUpTime=\"130412\"] m",
        format(input).c_str());
}

static void test_empty_fields_become_the_nil_value() {
    SyslogMessage input = message("");
    input.tag = "";
    input.hostname = "";
    TEST_ASSERT_EQUAL_STRING("<134>1 - - latchkey - - [meta sequenceId=\"4812\" sysUpTime=\"130412\"] -",
                             format(input).c_str());
}

static void test_a_long_tag_is_cut_to_32_characters() {
    SyslogMessage input = message("m");
    const std::string tag(40, 't');
    input.tag = tag;
    const std::string expected = "<134>1 - esp32s3-atom latchkey - " + std::string(32, 't') +
                                 " [meta sequenceId=\"4812\" sysUpTime=\"130412\"] m";
    TEST_ASSERT_EQUAL_STRING(expected.c_str(), format(input).c_str());
}

static void test_the_sequence_id_wraps_within_its_range() {
    SyslogMessage input = message("m");
    input.seq = 2147483647;
    TEST_ASSERT_NOT_NULL(std::strstr(format(input).c_str(), "sequenceId=\"2147483647\""));
    input.seq = 2147483648u;
    TEST_ASSERT_NOT_NULL(std::strstr(format(input).c_str(), "sequenceId=\"1\""));
}

static void test_a_message_too_long_is_cut_on_a_character_boundary() {
    const std::string text = std::string(300, 'a');
    std::string out = format(message(text), 200);
    TEST_ASSERT_EQUAL_UINT32(200, out.size());
    TEST_ASSERT_EQUAL_STRING("...", out.substr(out.size() - 3).c_str());
    const std::string accented = std::string(150, 'a') + "h\xc3\xa9llo world";
    for (size_t limit = 150; limit < 175; ++limit) {
        out = format(message(accented), limit);
        TEST_ASSERT_TRUE(out.size() <= limit);
        const size_t cut = out.size() - 3;
        TEST_ASSERT_TRUE(static_cast<unsigned char>(out[cut - 1]) != 0xc3);
    }
}

static void test_octet_counting_prefixes_the_byte_count() {
    std::string out = "stale";
    latchkey_util::frameOctetCounted(out, "<134>1 - h app - - - x");
    TEST_ASSERT_EQUAL_STRING("22 <134>1 - h app - - - x", out.c_str());
    latchkey_util::frameOctetCounted(out, "caf\xc3\xa9");
    TEST_ASSERT_EQUAL_STRING("5 caf\xc3\xa9", out.c_str());
}

static void test_app_names_are_1_to_48_printable_ascii_characters() {
    TEST_ASSERT_TRUE(latchkey_util::isSyslogAppName("latchkey"));
    TEST_ASSERT_TRUE(latchkey_util::isSyslogAppName(std::string(48, 'a')));
    TEST_ASSERT_TRUE(latchkey_util::isSyslogAppName("front-door_board.1"));
    TEST_ASSERT_FALSE(latchkey_util::isSyslogAppName(""));
    TEST_ASSERT_FALSE(latchkey_util::isSyslogAppName(std::string(49, 'a')));
    TEST_ASSERT_FALSE(latchkey_util::isSyslogAppName("a b"));
    TEST_ASSERT_FALSE(latchkey_util::isSyslogAppName("caf\xc3\xa9"));
    TEST_ASSERT_FALSE(latchkey_util::isSyslogAppName("tab\there"));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_each_level_maps_to_a_syslog_severity);
    RUN_TEST(test_a_synced_line_carries_every_rfc5424_field);
    RUN_TEST(test_an_unsynced_line_has_no_timestamp);
    RUN_TEST(test_the_priority_uses_facility_local0);
    RUN_TEST(test_timestamps_keep_milliseconds_and_pad_every_field);
    RUN_TEST(test_header_fields_hold_only_printable_ascii);
    RUN_TEST(test_empty_fields_become_the_nil_value);
    RUN_TEST(test_a_long_tag_is_cut_to_32_characters);
    RUN_TEST(test_the_sequence_id_wraps_within_its_range);
    RUN_TEST(test_a_message_too_long_is_cut_on_a_character_boundary);
    RUN_TEST(test_octet_counting_prefixes_the_byte_count);
    RUN_TEST(test_app_names_are_1_to_48_printable_ascii_characters);
    return UNITY_END();
}
