// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>
#include <cstring>
#include <string>

#include "latchkey_util/base32.h"

void setUp() {}

void tearDown() {}

static std::string encode(const char* text) {
    return latchkey_util::base32Encode(reinterpret_cast<const uint8_t*>(text), std::strlen(text));
}

static void test_rfc4648_vectors_without_padding() {
    TEST_ASSERT_EQUAL_STRING("", encode("").c_str());
    TEST_ASSERT_EQUAL_STRING("MY", encode("f").c_str());
    TEST_ASSERT_EQUAL_STRING("MZXQ", encode("fo").c_str());
    TEST_ASSERT_EQUAL_STRING("MZXW6", encode("foo").c_str());
    TEST_ASSERT_EQUAL_STRING("MZXW6YQ", encode("foob").c_str());
    TEST_ASSERT_EQUAL_STRING("MZXW6YTB", encode("fooba").c_str());
    TEST_ASSERT_EQUAL_STRING("MZXW6YTBOI", encode("foobar").c_str());
}

static void test_rfc6238_sha1_secret() {
    TEST_ASSERT_EQUAL_STRING("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", encode("12345678901234567890").c_str());
}

static void test_twenty_bytes_give_32_characters_of_the_alphabet() {
    uint8_t secret[20];
    for (size_t i = 0; i < sizeof(secret); ++i) {
        secret[i] = static_cast<uint8_t>(0xFF - i * 13);
    }
    const std::string encoded = latchkey_util::base32Encode(secret, sizeof(secret));
    TEST_ASSERT_EQUAL_UINT(32, encoded.size());
    for (char c : encoded) {
        TEST_ASSERT_TRUE((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7'));
    }
}

static void test_all_ones_and_all_zeros() {
    const uint8_t ones[5] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    const uint8_t zeros[5] = {0, 0, 0, 0, 0};
    TEST_ASSERT_EQUAL_STRING("77777777", latchkey_util::base32Encode(ones, sizeof(ones)).c_str());
    TEST_ASSERT_EQUAL_STRING("AAAAAAAA", latchkey_util::base32Encode(zeros, sizeof(zeros)).c_str());
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_rfc4648_vectors_without_padding);
    RUN_TEST(test_rfc6238_sha1_secret);
    RUN_TEST(test_twenty_bytes_give_32_characters_of_the_alphabet);
    RUN_TEST(test_all_ones_and_all_zeros);
    return UNITY_END();
}
