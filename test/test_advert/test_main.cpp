// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstddef>
#include <cstdint>

#include "../vectors/advert_vectors.h"
#include "ttlock/advert.h"

using ttlock::Bytes;

void setUp() {}

void tearDown() {}

static void test_factory_fresh_lock_advert() {
    const Bytes data{0x05, 0x03, 0x02, 0x1C, 0x3A, 0xB0, 0x00, 0xF4, 0xF9,
                     0x53, 0x65, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
    ttlock::Advert advert;
    TEST_ASSERT_TRUE(ttlock::parseAdvert(data, advert));
    TEST_ASSERT_EQUAL_UINT8(5, advert.version.protocolType);
    TEST_ASSERT_EQUAL_UINT8(3, advert.version.protocolVersion);
    TEST_ASSERT_EQUAL_UINT8(2, advert.version.scene);
    TEST_ASSERT_EQUAL_UINT16(0, advert.version.groupId);
    TEST_ASSERT_EQUAL_UINT16(0, advert.version.orgId);
    TEST_ASSERT_FALSE(advert.paired);
    TEST_ASSERT_FALSE(advert.hasLockState);
    TEST_ASSERT_FALSE(advert.locked);
    TEST_ASSERT_EQUAL_INT(58, advert.battery);
    TEST_ASSERT_EQUAL_STRING("11:22:33:44:55:66", advert.mac.c_str());
}

static void test_adverts_match_ttlock_ble() {
    for (const auto& c : vectors::advert::kAdverts) {
        ttlock::Advert advert;
        const bool ok = ttlock::parseAdvert(Bytes(c.data, c.data + c.size), advert);
        TEST_ASSERT_EQUAL_MESSAGE(c.ok, ok, c.name);
        if (!c.ok) {
            continue;
        }
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(c.protocolType, advert.version.protocolType, c.name);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(c.protocolVersion, advert.version.protocolVersion, c.name);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(c.scene, advert.version.scene, c.name);
        TEST_ASSERT_EQUAL_UINT16_MESSAGE(0, advert.version.groupId, c.name);
        TEST_ASSERT_EQUAL_UINT16_MESSAGE(0, advert.version.orgId, c.name);
        TEST_ASSERT_EQUAL_MESSAGE(c.paired, advert.paired, c.name);
        TEST_ASSERT_EQUAL_MESSAGE(c.hasLockState, advert.hasLockState, c.name);
        TEST_ASSERT_EQUAL_MESSAGE(c.locked, advert.locked, c.name);
        TEST_ASSERT_EQUAL_INT_MESSAGE(c.battery, advert.battery, c.name);
        TEST_ASSERT_EQUAL_STRING_MESSAGE(c.mac, advert.mac.c_str(), c.name);
    }
}

static void test_payload_without_the_leading_type_bytes_is_rejected() {
    const Bytes stripped{0x02, 0x1C, 0x3A, 0xB0, 0x00, 0xF4, 0xF9, 0x53,
                         0x65, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
    ttlock::Advert advert;
    TEST_ASSERT_FALSE(ttlock::parseAdvert(stripped, advert));
}

static void test_mac_is_the_reversed_tail_in_uppercase_hex() {
    const Bytes data{0x05, 0x03, 0x02, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45};
    ttlock::Advert advert;
    TEST_ASSERT_TRUE(ttlock::parseAdvert(data, advert));
    TEST_ASSERT_EQUAL_STRING("45:23:01:EF:CD:AB", advert.mac.c_str());
}

static void test_failed_parse_leaves_output_untouched() {
    ttlock::Advert advert;
    advert.battery = 7;
    advert.mac = "keep";
    TEST_ASSERT_FALSE(ttlock::parseAdvert(Bytes{0x05, 0x03, 0x02}, advert));
    TEST_ASSERT_EQUAL_INT(7, advert.battery);
    TEST_ASSERT_EQUAL_STRING("keep", advert.mac.c_str());
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_factory_fresh_lock_advert);
    RUN_TEST(test_adverts_match_ttlock_ble);
    RUN_TEST(test_payload_without_the_leading_type_bytes_is_rejected);
    RUN_TEST(test_mac_is_the_reversed_tail_in_uppercase_hex);
    RUN_TEST(test_failed_parse_leaves_output_untouched);
    return UNITY_END();
}
