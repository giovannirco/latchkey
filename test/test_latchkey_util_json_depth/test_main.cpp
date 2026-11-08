// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <string>

#include "latchkey_util/json_depth.h"

void setUp() {}

void tearDown() {}

static std::string repeated(const char* piece, size_t count) {
    std::string out;
    for (size_t i = 0; i < count; ++i) {
        out += piece;
    }
    return out;
}

static std::string nestedObjects(size_t depth) {
    return repeated("{\"a\":", depth - 1) + "{}" + repeated("}", depth - 1);
}

static void test_flat_and_empty_input() {
    TEST_ASSERT_TRUE(latchkey_util::jsonNestingWithin("", 1));
    TEST_ASSERT_TRUE(latchkey_util::jsonNestingWithin("not json at all", 1));
    TEST_ASSERT_TRUE(latchkey_util::jsonNestingWithin("{}", 1));
    TEST_ASSERT_TRUE(latchkey_util::jsonNestingWithin("{\"id\":1,\"method\":\"system.info\",\"params\":{}}", 2));
    TEST_ASSERT_FALSE(latchkey_util::jsonNestingWithin("{\"id\":1,\"method\":\"system.info\",\"params\":{}}", 1));
}

static void test_deep_arrays() {
    TEST_ASSERT_TRUE(latchkey_util::jsonNestingWithin(repeated("[", 8) + repeated("]", 8), 8));
    TEST_ASSERT_FALSE(latchkey_util::jsonNestingWithin(repeated("[", 9) + repeated("]", 9), 8));
    TEST_ASSERT_FALSE(latchkey_util::jsonNestingWithin(repeated("[", 1500), 8));
}

static void test_deep_objects() {
    TEST_ASSERT_TRUE(latchkey_util::jsonNestingWithin(nestedObjects(8), 8));
    TEST_ASSERT_FALSE(latchkey_util::jsonNestingWithin(nestedObjects(9), 8));
}

static void test_mixed_arrays_and_objects_count_together() {
    TEST_ASSERT_TRUE(latchkey_util::jsonNestingWithin("[{\"a\":[{\"b\":[{\"c\":[{}]}]}]}]", 8));
    TEST_ASSERT_FALSE(latchkey_util::jsonNestingWithin("[{\"a\":[{\"b\":[{\"c\":[{\"d\":[]}]}]}]}]", 8));
}

static void test_depth_falls_when_containers_close() {
    const std::string wide = repeated("[[[[[[[[]]]]]]]],", 50) + "[]";
    TEST_ASSERT_TRUE(latchkey_util::jsonNestingWithin("[" + wide + "]", 9));
    TEST_ASSERT_FALSE(latchkey_util::jsonNestingWithin("[" + wide + "]", 8));
}

static void test_brackets_inside_strings_do_not_count() {
    TEST_ASSERT_TRUE(latchkey_util::jsonNestingWithin("{\"s\":\"[[[[[[[[[[[[{{{{{{{{{{\"}", 1));
}

static void test_escaped_quotes_stay_inside_the_string() {
    TEST_ASSERT_TRUE(latchkey_util::jsonNestingWithin("{\"s\":\"\\\"[[[[[[[[[[[[\"}", 1));
    TEST_ASSERT_TRUE(latchkey_util::jsonNestingWithin("{\"s\":\"\\\\\\\"[[[[[[[[[[\"}", 1));
}

static void test_an_escaped_backslash_ends_before_the_closing_quote() {
    const std::string text = "{\"s\":\"\\\\\",\"t\":" + repeated("[", 10) + repeated("]", 10) + "}";
    TEST_ASSERT_FALSE(latchkey_util::jsonNestingWithin(text, 8));
    TEST_ASSERT_TRUE(latchkey_util::jsonNestingWithin(text, 11));
}

static void test_stray_closers_do_not_hide_depth() {
    TEST_ASSERT_TRUE(latchkey_util::jsonNestingWithin("]]]]}}}}{", 1));
    TEST_ASSERT_FALSE(latchkey_util::jsonNestingWithin("]]]]" + repeated("[", 9), 8));
}

static void test_an_unterminated_string_hides_nothing_after_it() {
    TEST_ASSERT_TRUE(latchkey_util::jsonNestingWithin("{\"s\":\"[[[[[[[[[[[[", 1));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_flat_and_empty_input);
    RUN_TEST(test_deep_arrays);
    RUN_TEST(test_deep_objects);
    RUN_TEST(test_mixed_arrays_and_objects_count_together);
    RUN_TEST(test_depth_falls_when_containers_close);
    RUN_TEST(test_brackets_inside_strings_do_not_count);
    RUN_TEST(test_escaped_quotes_stay_inside_the_string);
    RUN_TEST(test_an_escaped_backslash_ends_before_the_closing_quote);
    RUN_TEST(test_stray_closers_do_not_hide_depth);
    RUN_TEST(test_an_unterminated_string_hides_nothing_after_it);
    return UNITY_END();
}
