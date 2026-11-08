// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstring>
#include <string>
#include <vector>

#include "latchkey_util/line_buffer.h"

void setUp() {}

void tearDown() {}

struct Collector {
    std::vector<std::string> events;
    latchkey_util::LineBuffer buffer;

    explicit Collector(size_t maxLength)
        : buffer(
              maxLength, [this](std::string_view line) { events.emplace_back(line); },
              [this]() { events.emplace_back("<overflow>"); }) {}

    void feed(const char* text) { buffer.feed(text, std::strlen(text)); }

    std::string joined() const {
        std::string out;
        for (const auto& event : events) {
            out += event;
            out += '|';
        }
        return out;
    }
};

static void test_lines_end_at_newline() {
    Collector collector(16);
    collector.feed("a\nbc\n");
    TEST_ASSERT_EQUAL_STRING("a|bc|", collector.joined().c_str());
}

static void test_lines_can_arrive_in_pieces() {
    Collector collector(16);
    collector.feed("{\"id\"");
    collector.feed(":1}");
    TEST_ASSERT_EQUAL_STRING("", collector.joined().c_str());
    collector.feed("\n{");
    TEST_ASSERT_EQUAL_STRING("{\"id\":1}|", collector.joined().c_str());
}

static void test_carriage_returns_also_end_lines_and_empty_lines_are_dropped() {
    Collector collector(16);
    collector.feed("a\r\nb\r\r\n\n\nc\r");
    TEST_ASSERT_EQUAL_STRING("a|b|c|", collector.joined().c_str());
}

static void test_a_line_of_exactly_max_length_passes() {
    Collector collector(4);
    collector.feed("abcd\n");
    TEST_ASSERT_EQUAL_STRING("abcd|", collector.joined().c_str());
}

static void test_an_overlong_line_is_dropped_and_reported_once() {
    Collector collector(4);
    collector.feed("abc");
    collector.feed("defgh");
    collector.feed("ijk\nxy\n");
    TEST_ASSERT_EQUAL_STRING("<overflow>|xy|", collector.joined().c_str());
}

static void test_overflow_inside_one_chunk() {
    Collector collector(4);
    collector.feed("abcde\nfg\n");
    TEST_ASSERT_EQUAL_STRING("<overflow>|fg|", collector.joined().c_str());
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_lines_end_at_newline);
    RUN_TEST(test_lines_can_arrive_in_pieces);
    RUN_TEST(test_carriage_returns_also_end_lines_and_empty_lines_are_dropped);
    RUN_TEST(test_a_line_of_exactly_max_length_passes);
    RUN_TEST(test_an_overlong_line_is_dropped_and_reported_once);
    RUN_TEST(test_overflow_inside_one_chunk);
    return UNITY_END();
}
