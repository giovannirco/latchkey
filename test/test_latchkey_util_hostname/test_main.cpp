// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <string>

#include "latchkey_util/hostname.h"

void setUp() {}

void tearDown() {}

static void test_names_and_ipv4_addresses_pass() {
    const char* hosts[] = {"192.0.2.20", "logs.example.net", "a-b_c", "a", "a-", "LOGS.Example.NET"};
    for (const char* host : hosts) {
        TEST_ASSERT_TRUE_MESSAGE(latchkey_util::isHostname(host), host);
    }
    TEST_ASSERT_TRUE(latchkey_util::isHostname(std::string(64, 'a')));
}

static void test_empty_labels_spaces_and_long_names_are_refused() {
    const char* hosts[] = {"", ".a", "a.", "a..b", "a b", "a/b", "a:514", "caf\xc3\xa9", "a\tb", "[2001:db8::1]"};
    for (const char* host : hosts) {
        TEST_ASSERT_FALSE_MESSAGE(latchkey_util::isHostname(host), host);
    }
    TEST_ASSERT_FALSE(latchkey_util::isHostname(std::string(65, 'a')));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_names_and_ipv4_addresses_pass);
    RUN_TEST(test_empty_labels_spaces_and_long_names_are_refused);
    return UNITY_END();
}
