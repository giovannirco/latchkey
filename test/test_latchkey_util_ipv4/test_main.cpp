// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>

#include "latchkey_util/ipv4.h"

void setUp() {}

void tearDown() {}

static uint32_t parsed(const char* text) {
    uint32_t address = 0xDEADBEEF;
    TEST_ASSERT_TRUE_MESSAGE(latchkey_util::parseIpv4(text, address), text);
    return address;
}

static void rejected(const char* text) {
    uint32_t address = 0;
    TEST_ASSERT_FALSE_MESSAGE(latchkey_util::parseIpv4(text, address), text);
}

static void test_parses_dotted_quads_in_host_order() {
    TEST_ASSERT_EQUAL_HEX32(0xC0000201, parsed("192.0.2.1"));
    TEST_ASSERT_EQUAL_HEX32(0x00000000, parsed("0.0.0.0"));
    TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, parsed("255.255.255.255"));
    TEST_ASSERT_EQUAL_HEX32(0xC6336435, parsed("198.51.100.53"));
}

static void test_rejects_anything_but_four_decimal_octets() {
    rejected("");
    rejected("1.2.3");
    rejected("1.2.3.4.5");
    rejected("256.1.1.1");
    rejected("1.2.3.999");
    rejected("01.2.3.4");
    rejected("1.2.3.04");
    rejected("1..3.4");
    rejected(".1.2.3");
    rejected("1.2.3.4.");
    rejected(" 1.2.3.4");
    rejected("1.2.3.4 ");
    rejected("0x7f.0.0.1");
    rejected("1.2.3.-4");
    rejected("1.2.3.+4");
    rejected("1234.1.1.1");
    rejected("a.b.c.d");
}

static void test_netmasks_are_contiguous_and_not_empty() {
    TEST_ASSERT_TRUE(latchkey_util::isNetmask(0xFFFFFF00));
    TEST_ASSERT_TRUE(latchkey_util::isNetmask(0xFFFF0000));
    TEST_ASSERT_TRUE(latchkey_util::isNetmask(0x80000000));
    TEST_ASSERT_TRUE(latchkey_util::isNetmask(0xFFFFFFFC));
    TEST_ASSERT_FALSE(latchkey_util::isNetmask(0x00000000));
    TEST_ASSERT_FALSE(latchkey_util::isNetmask(0xFF00FF00));
    TEST_ASSERT_FALSE(latchkey_util::isNetmask(0x00FFFFFF));
    TEST_ASSERT_FALSE(latchkey_util::isNetmask(0xFFFFFF01));
    TEST_ASSERT_FALSE(latchkey_util::isNetmask(0xFFFFFFFE));
    TEST_ASSERT_FALSE(latchkey_util::isNetmask(0xFFFFFFFF));
}

static void test_static_config_needs_hosts_in_one_subnet() {
    const uint32_t mask = 0xFFFFFF00;
    TEST_ASSERT_TRUE(latchkey_util::isStaticIpv4(0xC000023E, 0xC0000201, mask));
    TEST_ASSERT_FALSE(latchkey_util::isStaticIpv4(0xC000033E, 0xC0000201, mask));
    TEST_ASSERT_FALSE(latchkey_util::isStaticIpv4(0xC0000201, 0xC0000201, mask));
    TEST_ASSERT_FALSE(latchkey_util::isStaticIpv4(0xC0000200, 0xC0000201, mask));
    TEST_ASSERT_FALSE(latchkey_util::isStaticIpv4(0xC00002FF, 0xC0000201, mask));
    TEST_ASSERT_FALSE(latchkey_util::isStaticIpv4(0xC000023E, 0xC00002FF, mask));
    TEST_ASSERT_FALSE(latchkey_util::isStaticIpv4(0xC000023E, 0xC0000201, 0xFF00FF00));
    TEST_ASSERT_TRUE(latchkey_util::isStaticIpv4(0xC0000202, 0xC0000201, 0xFFFFFFFC));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_parses_dotted_quads_in_host_order);
    RUN_TEST(test_rejects_anything_but_four_decimal_octets);
    RUN_TEST(test_netmasks_are_contiguous_and_not_empty);
    RUN_TEST(test_static_config_needs_hosts_in_one_subnet);
    return UNITY_END();
}
