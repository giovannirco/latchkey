// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <deque>
#include <optional>

#include "latchkey_util/backlog.h"

void setUp() {}

void tearDown() {}

struct Line {
    int id;
    bool broadcast;
};

static bool disposable(const Line& line) { return line.broadcast; }

static std::optional<Line> push(std::deque<Line>& queue, Line line) {
    return latchkey_util::pushBounded(queue, line, 3, disposable);
}

static void test_nothing_is_dropped_below_the_capacity() {
    std::deque<Line> queue;
    TEST_ASSERT_FALSE(push(queue, {1, true}).has_value());
    TEST_ASSERT_FALSE(push(queue, {2, false}).has_value());
    TEST_ASSERT_FALSE(push(queue, {3, true}).has_value());
    TEST_ASSERT_EQUAL_size_t(3, queue.size());
}

static void test_the_oldest_disposable_line_goes_first() {
    std::deque<Line> queue{{1, false}, {2, true}, {3, true}};
    const std::optional<Line> dropped = push(queue, {4, false});
    TEST_ASSERT_TRUE(dropped.has_value());
    TEST_ASSERT_EQUAL_INT(2, dropped->id);
    TEST_ASSERT_EQUAL_size_t(3, queue.size());
    TEST_ASSERT_EQUAL_INT(1, queue[0].id);
    TEST_ASSERT_EQUAL_INT(3, queue[1].id);
    TEST_ASSERT_EQUAL_INT(4, queue[2].id);
}

static void test_the_oldest_line_goes_when_none_is_disposable() {
    std::deque<Line> queue{{1, false}, {2, false}, {3, false}};
    const std::optional<Line> dropped = push(queue, {4, true});
    TEST_ASSERT_TRUE(dropped.has_value());
    TEST_ASSERT_EQUAL_INT(1, dropped->id);
    TEST_ASSERT_EQUAL_INT(2, queue.front().id);
    TEST_ASSERT_EQUAL_INT(4, queue.back().id);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_nothing_is_dropped_below_the_capacity);
    RUN_TEST(test_the_oldest_disposable_line_goes_first);
    RUN_TEST(test_the_oldest_line_goes_when_none_is_disposable);
    return UNITY_END();
}
