// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>

#include "latchkey_util/password_record.h"

using latchkey_util::PasswordRecord;
using latchkey_util::PasswordRecordBytes;

void setUp() {}

void tearDown() {}

static PasswordRecord sample(uint32_t iterations) {
    PasswordRecord record;
    for (size_t i = 0; i < record.salt.size(); ++i) {
        record.salt[i] = static_cast<uint8_t>(0x10 + i);
    }
    record.iterations = iterations;
    for (size_t i = 0; i < record.hash.size(); ++i) {
        record.hash[i] = static_cast<uint8_t>(0xA0 + i);
    }
    return record;
}

static bool decode(const PasswordRecordBytes& bytes, size_t length, PasswordRecord& out) {
    return latchkey_util::decodePasswordRecord(bytes.data(), length, out);
}

static void test_the_record_is_one_versioned_item() {
    TEST_ASSERT_EQUAL_size_t(53, latchkey_util::kPasswordRecordSize);
    const PasswordRecordBytes bytes = latchkey_util::encodePasswordRecord(sample(0x01020304));
    TEST_ASSERT_EQUAL_HEX8(latchkey_util::kPasswordRecordVersion, bytes[0]);
    TEST_ASSERT_EQUAL_HEX8(1, bytes[0]);
    for (size_t i = 0; i < latchkey_util::kPasswordSaltSize; ++i) {
        TEST_ASSERT_EQUAL_HEX8(0x10 + i, bytes[1 + i]);
    }
    TEST_ASSERT_EQUAL_HEX8(0x04, bytes[17]);
    TEST_ASSERT_EQUAL_HEX8(0x03, bytes[18]);
    TEST_ASSERT_EQUAL_HEX8(0x02, bytes[19]);
    TEST_ASSERT_EQUAL_HEX8(0x01, bytes[20]);
    for (size_t i = 0; i < latchkey_util::kPasswordHashSize; ++i) {
        TEST_ASSERT_EQUAL_HEX8(0xA0 + i, bytes[21 + i]);
    }
}

static void test_a_record_survives_a_round_trip() {
    const PasswordRecord original = sample(4400);
    PasswordRecord decoded;
    TEST_ASSERT_TRUE(decode(latchkey_util::encodePasswordRecord(original), latchkey_util::kPasswordRecordSize, decoded));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(original.salt.data(), decoded.salt.data(), original.salt.size());
    TEST_ASSERT_EQUAL_UINT32(4400, decoded.iterations);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(original.hash.data(), decoded.hash.data(), original.hash.size());
}

static void test_a_record_of_another_length_is_refused() {
    const PasswordRecordBytes bytes = latchkey_util::encodePasswordRecord(sample(4400));
    PasswordRecord decoded;
    TEST_ASSERT_FALSE(decode(bytes, latchkey_util::kPasswordRecordSize - 1, decoded));
    TEST_ASSERT_FALSE(decode(bytes, 0, decoded));
    uint8_t longer[latchkey_util::kPasswordRecordSize + 1] = {};
    for (size_t i = 0; i < bytes.size(); ++i) {
        longer[i] = bytes[i];
    }
    TEST_ASSERT_FALSE(latchkey_util::decodePasswordRecord(longer, sizeof(longer), decoded));
}

static void test_a_record_of_another_version_is_refused() {
    PasswordRecordBytes bytes = latchkey_util::encodePasswordRecord(sample(4400));
    PasswordRecord decoded;
    bytes[0] = 0;
    TEST_ASSERT_FALSE(decode(bytes, bytes.size(), decoded));
    bytes[0] = 2;
    TEST_ASSERT_FALSE(decode(bytes, bytes.size(), decoded));
}

static void test_a_record_without_iterations_is_refused() {
    PasswordRecord decoded;
    TEST_ASSERT_FALSE(decode(latchkey_util::encodePasswordRecord(sample(0)), latchkey_util::kPasswordRecordSize, decoded));
}

static void test_a_refused_record_leaves_the_output_alone() {
    PasswordRecordBytes bytes = latchkey_util::encodePasswordRecord(sample(4400));
    bytes[0] = 9;
    PasswordRecord decoded = sample(77);
    TEST_ASSERT_FALSE(decode(bytes, bytes.size(), decoded));
    TEST_ASSERT_EQUAL_UINT32(77, decoded.iterations);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_the_record_is_one_versioned_item);
    RUN_TEST(test_a_record_survives_a_round_trip);
    RUN_TEST(test_a_record_of_another_length_is_refused);
    RUN_TEST(test_a_record_of_another_version_is_refused);
    RUN_TEST(test_a_record_without_iterations_is_refused);
    RUN_TEST(test_a_refused_record_leaves_the_output_alone);
    return UNITY_END();
}
