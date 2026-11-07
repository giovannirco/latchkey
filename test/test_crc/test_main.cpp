// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstddef>
#include <cstdint>

#include "../vectors/codec_vectors.h"
#include "../vectors/crc_vectors.h"
#include "ttlock/codec_xor.h"
#include "ttlock/crc8.h"

void setUp() {}

void tearDown() {}

static uint8_t dallasMaximBitwise(const uint8_t* data, size_t len) {
    uint8_t crc = 0;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc & 1) ? static_cast<uint8_t>((crc >> 1) ^ 0x8C) : static_cast<uint8_t>(crc >> 1);
        }
    }
    return crc;
}

static void assertBytes(const uint8_t* expected, size_t expectedSize, const ttlock::Bytes& actual, const char* name) {
    TEST_ASSERT_EQUAL_UINT_MESSAGE(expectedSize, actual.size(), name);
    if (expectedSize > 0) {
        TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected, actual.data(), expectedSize, name);
    }
}

static void test_check_value_of_123456789_is_0xa1() {
    TEST_ASSERT_EQUAL_HEX8(0xA1, ttlock::crc8(reinterpret_cast<const uint8_t*>("123456789"), 9));
    TEST_ASSERT_EQUAL_HEX8(vectors::crc::kCheckValue,
                           ttlock::crc8(vectors::crc::kCheckInput, sizeof(vectors::crc::kCheckInput)));
}

static void test_empty_input_is_zero() {
    TEST_ASSERT_EQUAL_HEX8(0x00, ttlock::crc8(nullptr, 0));
}

static void test_every_single_byte_matches_the_ttlock_ble_table() {
    for (unsigned i = 0; i < 256; ++i) {
        const uint8_t byte = static_cast<uint8_t>(i);
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(vectors::crc::kTable[i], ttlock::crc8(&byte, 1), "table entry");
    }
}

static void test_table_is_dallas_maxim_except_entry_0x21() {
    for (unsigned i = 0; i < 256; ++i) {
        const uint8_t byte = static_cast<uint8_t>(i);
        const uint8_t expected = (i == 0x21) ? 0x07 : dallasMaximBitwise(&byte, 1);
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(expected, ttlock::crc8(&byte, 1), "table entry");
    }
    const uint8_t quirk = 0x21;
    TEST_ASSERT_EQUAL_HEX8(0x7D, dallasMaximBitwise(&quirk, 1));
}

static void test_frame_crcs_match_ttlock_ble() {
    for (const auto& frame : vectors::crc::kFrames) {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(frame.crc, ttlock::crc8(frame.data, frame.size), frame.name);
    }
}

static void test_frame_vector_through_entry_0x21_differs_from_plain_dallas() {
    const auto& quirk = vectors::crc::kFrames[6];
    TEST_ASSERT_EQUAL_STRING("crc_table_quirk", quirk.name);
    TEST_ASSERT_EQUAL_HEX8(quirk.crc, ttlock::crc8(quirk.data, quirk.size));
    TEST_ASSERT_NOT_EQUAL(quirk.crc, dallasMaximBitwise(quirk.data, quirk.size));
}

static void test_real_lock_captures_from_kind3r_match() {
    for (const auto& capture : vectors::crc::kKind3rCaptures) {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(capture.crc, ttlock::crc8(capture.data, capture.size), capture.name);
    }
}

static void test_kind3r_bad_crc_captures_are_wrong_only_under_plain_dallas() {
    for (size_t i = 0; i < 2; ++i) {
        const auto& capture = vectors::crc::kKind3rCaptures[i];
        TEST_ASSERT_NOT_EQUAL_MESSAGE(capture.crc, dallasMaximBitwise(capture.data, capture.size), capture.name);
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(capture.crc, ttlock::crc8(capture.data, capture.size), capture.name);
    }
}

static void test_xor_codec_decodes_like_ttlock_ble() {
    for (const auto& c : vectors::codec::kCases) {
        const ttlock::Bytes encoded(c.encoded, c.encoded + c.size);
        assertBytes(c.plain, c.size, ttlock::xorCodec(encoded, c.seed), c.name);
    }
}

static void test_xor_codec_encodes_back_to_the_wire_bytes() {
    for (const auto& c : vectors::codec::kCases) {
        const ttlock::Bytes plain(c.plain, c.plain + c.size);
        assertBytes(c.encoded, c.size, ttlock::xorCodec(plain, c.seed), c.name);
    }
}

static void test_xor_codec_of_empty_input_is_empty() {
    TEST_ASSERT_TRUE(ttlock::xorCodec(ttlock::Bytes{}, 0x5A).empty());
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_check_value_of_123456789_is_0xa1);
    RUN_TEST(test_empty_input_is_zero);
    RUN_TEST(test_every_single_byte_matches_the_ttlock_ble_table);
    RUN_TEST(test_table_is_dallas_maxim_except_entry_0x21);
    RUN_TEST(test_frame_crcs_match_ttlock_ble);
    RUN_TEST(test_frame_vector_through_entry_0x21_differs_from_plain_dallas);
    RUN_TEST(test_real_lock_captures_from_kind3r_match);
    RUN_TEST(test_kind3r_bad_crc_captures_are_wrong_only_under_plain_dallas);
    RUN_TEST(test_xor_codec_decodes_like_ttlock_ble);
    RUN_TEST(test_xor_codec_encodes_back_to_the_wire_bytes);
    RUN_TEST(test_xor_codec_of_empty_input_is_empty);
    return UNITY_END();
}
