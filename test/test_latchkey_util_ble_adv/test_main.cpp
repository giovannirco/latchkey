// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstddef>
#include <cstdint>
#include <string>

#include "latchkey_util/ble_adv.h"
#include "ttlock/advert.h"

using latchkey_util::AdField;

void setUp() {}

void tearDown() {}

static constexpr uint8_t kFactoryAdvert[] = {
    0x02, 0x01, 0x06,
    0x03, 0x03, 0x10, 0x19,
    0x12, 0xFF, 0x05, 0x03, 0x02, 0x1C, 0x3A, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
};

static constexpr uint8_t kNamedAdvert[] = {
    0x02, 0x01, 0x06,
    0x06, 0x09, 'S', '3', '1', '_', 'x',
    0x05, 0x02, 0x0F, 0x18, 0x10, 0x19,
};

static void test_manufacturer_field_keeps_the_two_leading_bytes() {
    AdField field;
    TEST_ASSERT_TRUE(latchkey_util::findAdField(kFactoryAdvert, sizeof(kFactoryAdvert), 0xFF, field));
    TEST_ASSERT_EQUAL_UINT8(0xFF, field.type);
    TEST_ASSERT_EQUAL_UINT(17, field.size);
    TEST_ASSERT_EQUAL_HEX8(0x05, field.data[0]);
    TEST_ASSERT_EQUAL_HEX8(0x03, field.data[1]);
    TEST_ASSERT_EQUAL_HEX8(0x11, field.data[field.size - 1]);
}

static void test_the_manufacturer_field_parses_as_a_v3_ttlock_advert() {
    AdField field;
    TEST_ASSERT_TRUE(latchkey_util::findAdField(kFactoryAdvert, sizeof(kFactoryAdvert), 0xFF, field));
    ttlock::Advert advert;
    TEST_ASSERT_TRUE(ttlock::parseAdvert(ttlock::Bytes(field.data, field.data + field.size), advert));
    TEST_ASSERT_EQUAL_UINT8(5, advert.version.protocolType);
    TEST_ASSERT_EQUAL_UINT8(3, advert.version.protocolVersion);
    TEST_ASSERT_FALSE(advert.paired);
    TEST_ASSERT_FALSE(advert.hasLockState);
    TEST_ASSERT_EQUAL_INT(58, advert.battery);
    TEST_ASSERT_EQUAL_STRING("11:22:33:44:55:66", advert.mac.c_str());
}

static void test_finds_a_field_after_others_and_reports_missing_ones() {
    AdField field;
    TEST_ASSERT_TRUE(latchkey_util::findAdField(kNamedAdvert, sizeof(kNamedAdvert), 0x09, field));
    TEST_ASSERT_EQUAL_UINT(5, field.size);
    TEST_ASSERT_EQUAL_STRING("S31_x", std::string(reinterpret_cast<const char*>(field.data), field.size).c_str());
    TEST_ASSERT_FALSE(latchkey_util::findAdField(kNamedAdvert, sizeof(kNamedAdvert), 0xFF, field));
    TEST_ASSERT_FALSE(latchkey_util::findAdField(kNamedAdvert, 0, 0x01, field));
    TEST_ASSERT_FALSE(latchkey_util::findAdField(nullptr, 0, 0x01, field));
}

static void test_a_field_that_overruns_the_payload_is_not_returned() {
    const uint8_t truncated[] = {0x02, 0x01, 0x06, 0x12, 0xFF, 0x05, 0x03, 0x02};
    AdField field;
    TEST_ASSERT_FALSE(latchkey_util::findAdField(truncated, sizeof(truncated), 0xFF, field));
    TEST_ASSERT_TRUE(latchkey_util::findAdField(truncated, sizeof(truncated), 0x01, field));
    TEST_ASSERT_EQUAL_UINT(1, field.size);
}

static void test_a_zero_length_ends_the_significant_part() {
    const uint8_t padded[] = {0x02, 0x01, 0x06, 0x00, 0x03, 0xFF, 0x05, 0x03};
    AdField field;
    TEST_ASSERT_FALSE(latchkey_util::findAdField(padded, sizeof(padded), 0xFF, field));
}

static void test_a_type_without_data_has_size_zero() {
    const uint8_t empty[] = {0x01, 0x09, 0x02, 0x01, 0x06};
    AdField field;
    TEST_ASSERT_TRUE(latchkey_util::findAdField(empty, sizeof(empty), 0x09, field));
    TEST_ASSERT_EQUAL_UINT(0, field.size);
    TEST_ASSERT_TRUE(latchkey_util::findAdField(empty, sizeof(empty), 0x01, field));
    TEST_ASSERT_EQUAL_HEX8(0x06, field.data[0]);
}

static void test_uuid16_lists_are_searched_in_complete_and_incomplete_form() {
    TEST_ASSERT_TRUE(latchkey_util::hasUuid16(kFactoryAdvert, sizeof(kFactoryAdvert), 0x1910));
    TEST_ASSERT_TRUE(latchkey_util::hasUuid16(kNamedAdvert, sizeof(kNamedAdvert), 0x1910));
    TEST_ASSERT_TRUE(latchkey_util::hasUuid16(kNamedAdvert, sizeof(kNamedAdvert), 0x180F));
    TEST_ASSERT_FALSE(latchkey_util::hasUuid16(kNamedAdvert, sizeof(kNamedAdvert), 0x1019));
    const uint8_t odd[] = {0x04, 0x03, 0x10, 0x19, 0x0F};
    TEST_ASSERT_TRUE(latchkey_util::hasUuid16(odd, sizeof(odd), 0x1910));
    TEST_ASSERT_FALSE(latchkey_util::hasUuid16(odd, sizeof(odd), 0x000F));
    TEST_ASSERT_FALSE(latchkey_util::hasUuid16(kFactoryAdvert, 3, 0x1910));
}

static void test_addresses_print_most_significant_octet_first() {
    const uint8_t littleEndian[6] = {0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
    TEST_ASSERT_EQUAL_STRING("11:22:33:44:55:66", latchkey_util::formatBleAddress(littleEndian).c_str());
    const uint8_t hex[6] = {0x0F, 0xAB, 0x00, 0x5A, 0xE1, 0xD4};
    TEST_ASSERT_EQUAL_STRING("D4:E1:5A:00:AB:0F", latchkey_util::formatBleAddress(hex).c_str());
}

static void test_addresses_parse_back_to_little_endian_in_either_case() {
    uint8_t parsed[6] = {};
    TEST_ASSERT_TRUE(latchkey_util::parseBleAddress("11:22:33:44:55:66", parsed));
    const uint8_t expected[6] = {0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, parsed, 6);
    TEST_ASSERT_TRUE(latchkey_util::parseBleAddress("d4:e1:5a:00:ab:0f", parsed));
    TEST_ASSERT_EQUAL_STRING("D4:E1:5A:00:AB:0F", latchkey_util::formatBleAddress(parsed).c_str());
}

static void test_malformed_addresses_are_refused_and_leave_the_output_alone() {
    const char* bad[] = {
        "",
        "11:22:33:44:55",
        "11:22:33:44:55:66:77",
        "11-22-33-44-55-66",
        "112233445566",
        "11:22:33:44:55:6G",
        "11:22:33:44:55:6",
        " 11:22:33:44:55:66",
        "11:22:33:44:55:66 ",
        "1:122:33:44:55:66",
    };
    for (const char* text : bad) {
        uint8_t parsed[6] = {1, 2, 3, 4, 5, 6};
        TEST_ASSERT_FALSE_MESSAGE(latchkey_util::parseBleAddress(text, parsed), text);
        const uint8_t untouched[6] = {1, 2, 3, 4, 5, 6};
        TEST_ASSERT_EQUAL_HEX8_ARRAY(untouched, parsed, 6);
    }
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_manufacturer_field_keeps_the_two_leading_bytes);
    RUN_TEST(test_the_manufacturer_field_parses_as_a_v3_ttlock_advert);
    RUN_TEST(test_finds_a_field_after_others_and_reports_missing_ones);
    RUN_TEST(test_a_field_that_overruns_the_payload_is_not_returned);
    RUN_TEST(test_a_zero_length_ends_the_significant_part);
    RUN_TEST(test_a_type_without_data_has_size_zero);
    RUN_TEST(test_uuid16_lists_are_searched_in_complete_and_incomplete_form);
    RUN_TEST(test_addresses_print_most_significant_octet_first);
    RUN_TEST(test_addresses_parse_back_to_little_endian_in_either_case);
    RUN_TEST(test_malformed_addresses_are_refused_and_leave_the_output_alone);
    return UNITY_END();
}
