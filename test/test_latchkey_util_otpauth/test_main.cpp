// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>
#include <string>

#include "latchkey_util/otpauth.h"

void setUp() {}

void tearDown() {}

static const uint8_t kRfc6238Secret[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
                                         '1', '2', '3', '4', '5', '6', '7', '8', '9', '0'};

static void test_uri_for_a_board_name() {
    const std::string uri = latchkey_util::otpauthUri("esp32s3-atom", kRfc6238Secret, sizeof(kRfc6238Secret));
    TEST_ASSERT_EQUAL_STRING("otpauth://totp/Latchkey:esp32s3-atom?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
                             "&issuer=Latchkey&algorithm=SHA1&digits=6&period=30",
                             uri.c_str());
}

static void test_account_is_percent_encoded() {
    const std::string uri = latchkey_util::otpauthUri("a b:c/d?e&f%g~h_i.j-k", kRfc6238Secret, 5);
    TEST_ASSERT_EQUAL_STRING("otpauth://totp/Latchkey:a%20b%3Ac%2Fd%3Fe%26f%25g~h_i.j-k?secret=GEZDGNBV"
                             "&issuer=Latchkey&algorithm=SHA1&digits=6&period=30",
                             uri.c_str());
}

static void test_non_ascii_bytes_are_percent_encoded_in_upper_hex() {
    const std::string uri = latchkey_util::otpauthUri("\xC3\xA9", kRfc6238Secret, 5);
    TEST_ASSERT_EQUAL_STRING("otpauth://totp/Latchkey:%C3%A9?secret=GEZDGNBV"
                             "&issuer=Latchkey&algorithm=SHA1&digits=6&period=30",
                             uri.c_str());
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_uri_for_a_board_name);
    RUN_TEST(test_account_is_percent_encoded);
    RUN_TEST(test_non_ascii_bytes_are_percent_encoded_in_upper_hex);
    return UNITY_END();
}
