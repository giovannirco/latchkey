// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <string>

#include "latchkey_util/label.h"

void setUp() {}

void tearDown() {}

static std::string normalized(const std::string& input, size_t maxCodePoints = 32) {
    std::string out = "untouched";
    TEST_ASSERT_TRUE_MESSAGE(latchkey_util::normalizeLabel(input, maxCodePoints, out), input.c_str());
    return out;
}

static void assertRefused(const std::string& input, size_t maxCodePoints = 32) {
    std::string out = "untouched";
    TEST_ASSERT_FALSE_MESSAGE(latchkey_util::normalizeLabel(input, maxCodePoints, out), input.c_str());
    TEST_ASSERT_EQUAL_STRING("untouched", out.c_str());
}

static void test_keeps_a_plain_name() { TEST_ASSERT_EQUAL_STRING("Front door", normalized("Front door").c_str()); }

static void test_trims_surrounding_whitespace_only() {
    TEST_ASSERT_EQUAL_STRING("Shed  door", normalized(" \t Shed  door \r\n").c_str());
}

static void test_refuses_empty_and_blank_names() {
    assertRefused("");
    assertRefused("   ");
    assertRefused("\t\n");
}

static void test_counts_code_points_not_bytes() {
    const std::string accented = "Porta da cozinha \xC3\xA7\xC3\xA3o";
    TEST_ASSERT_EQUAL_STRING(accented.c_str(), normalized(accented, 20).c_str());
    assertRefused(accented, 19);
    TEST_ASSERT_EQUAL_STRING("\xF0\x9F\x94\x92", normalized("\xF0\x9F\x94\x92", 1).c_str());
}

static void test_limit_is_inclusive() {
    TEST_ASSERT_EQUAL_STRING("abcd", normalized("abcd", 4).c_str());
    assertRefused("abcde", 4);
}

static void test_refuses_control_characters_inside() {
    assertRefused("Front\tdoor");
    assertRefused(std::string("Front\0door", 10));
    assertRefused("Front\x7F" "door");
}

static void test_refuses_invalid_utf8() {
    assertRefused("caf\xC3");
    assertRefused("\xC3\x28");
    assertRefused("\xC0\xAF");
    assertRefused("\xE0\x80\xAF");
    assertRefused("\xED\xA0\x80");
    assertRefused("\xF4\x90\x80\x80");
    assertRefused("\x80");
    assertRefused("\xFF");
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_keeps_a_plain_name);
    RUN_TEST(test_trims_surrounding_whitespace_only);
    RUN_TEST(test_refuses_empty_and_blank_names);
    RUN_TEST(test_counts_code_points_not_bytes);
    RUN_TEST(test_limit_is_inclusive);
    RUN_TEST(test_refuses_control_characters_inside);
    RUN_TEST(test_refuses_invalid_utf8);
    return UNITY_END();
}
