// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstring>
#include <string>
#include <vector>

#include "../reference/allocation_failure.h"
#include "latchkey_util/line_buffer.h"

void setUp() { allocation_failure::reset(); }

void tearDown() { allocation_failure::resume(); }

struct Collector {
    std::vector<std::string> events;
    latchkey_util::LineBuffer buffer;

    explicit Collector(size_t maxLength)
        : buffer(
              maxLength, [this](latchkey_util::RpcText line) { events.emplace_back(line.view()); },
              [this](latchkey_util::LineBuffer::Error) { events.emplace_back("<overflow>"); }) {}

    void feed(const char* text) {
        std::string chunk(text);
        buffer.consume(chunk.data(), chunk.size());
    }

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

static void test_allocation_failure_discards_the_whole_line_and_recovers() {
    Collector collector(16384);
    allocation_failure::failNext();
    collector.feed("secret request\n");
    allocation_failure::resume();
    collector.feed("next\n");
    TEST_ASSERT_EQUAL_STRING("<overflow>|next|", collector.joined().c_str());
}

static void test_consumed_input_is_erased_before_the_completed_line_runs() {
    char chunk[] = "owned secret\n";
    bool called = false;
    latchkey_util::LineBuffer buffer(16384, [&](latchkey_util::RpcText line) {
        called = true;
        TEST_ASSERT_EQUAL_STRING("owned secret", line.c_str());
        for (char byte : chunk) TEST_ASSERT_EQUAL_INT(0, byte);
    }, [](auto) { TEST_FAIL_MESSAGE("unexpected input error"); });
    buffer.consume(chunk, sizeof(chunk) - 1);
    TEST_ASSERT_TRUE(called);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_lines_end_at_newline);
    RUN_TEST(test_lines_can_arrive_in_pieces);
    RUN_TEST(test_carriage_returns_also_end_lines_and_empty_lines_are_dropped);
    RUN_TEST(test_a_line_of_exactly_max_length_passes);
    RUN_TEST(test_an_overlong_line_is_dropped_and_reported_once);
    RUN_TEST(test_overflow_inside_one_chunk);
    RUN_TEST(test_allocation_failure_discards_the_whole_line_and_recovers);
    RUN_TEST(test_consumed_input_is_erased_before_the_completed_line_runs);
    return UNITY_END();
}
