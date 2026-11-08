// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <array>
#include <cstdint>

#include "latchkey_util/seed_table.h"

using latchkey_util::SeedTable;

void setUp() {}

void tearDown() {}

static SeedTable sample() {
    SeedTable table;
    table.year = 2025;
    table.confirmed = true;
    for (size_t i = 0; i < table.seeds.size(); ++i) {
        table.seeds[i].code = static_cast<uint16_t>(0x0100 + i);
        table.seeds[i].secret = 0x0102030405060708ULL + i;
    }
    return table;
}

static void test_the_table_encodes_byte_for_byte() {
    TEST_ASSERT_EQUAL_UINT(104, latchkey_util::kSeedTableSize);
    const auto bytes = latchkey_util::encodeSeedTable(sample());
    const uint8_t head[] = {0x01, 0x01, 0x07, 0xe9, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                            0x01, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(head, bytes.data(), sizeof(head));
    const uint8_t tail[] = {0x01, 0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x11};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(tail, bytes.data() + bytes.size() - sizeof(tail), sizeof(tail));
}

static void test_an_unconfirmed_table_says_so() {
    SeedTable table = sample();
    table.confirmed = false;
    const auto bytes = latchkey_util::encodeSeedTable(table);
    TEST_ASSERT_EQUAL_UINT8(0x00, bytes[1]);
    SeedTable out;
    TEST_ASSERT_TRUE(latchkey_util::decodeSeedTable(bytes.data(), bytes.size(), out));
    TEST_ASSERT_FALSE(out.confirmed);
}

static void test_the_table_survives_a_round_trip() {
    const SeedTable table = sample();
    const auto bytes = latchkey_util::encodeSeedTable(table);
    SeedTable out;
    TEST_ASSERT_TRUE(latchkey_util::decodeSeedTable(bytes.data(), bytes.size(), out));
    TEST_ASSERT_EQUAL_UINT16(2025, out.year);
    TEST_ASSERT_TRUE(out.confirmed);
    for (size_t i = 0; i < out.seeds.size(); ++i) {
        TEST_ASSERT_EQUAL_UINT16(table.seeds[i].code, out.seeds[i].code);
        TEST_ASSERT_EQUAL_UINT64(table.seeds[i].secret, out.seeds[i].secret);
    }
}

static void test_damaged_blobs_are_refused_and_leave_the_output_alone() {
    const auto good = latchkey_util::encodeSeedTable(sample());
    std::array<uint8_t, latchkey_util::kSeedTableSize> wrongVersion = good;
    wrongVersion[0] = 0x02;
    std::array<uint8_t, latchkey_util::kSeedTableSize> wrongFlag = good;
    wrongFlag[1] = 0x02;
    SeedTable out;
    out.year = 1999;
    TEST_ASSERT_FALSE(latchkey_util::decodeSeedTable(good.data(), good.size() - 1, out));
    TEST_ASSERT_FALSE(latchkey_util::decodeSeedTable(wrongVersion.data(), wrongVersion.size(), out));
    TEST_ASSERT_FALSE(latchkey_util::decodeSeedTable(wrongFlag.data(), wrongFlag.size(), out));
    TEST_ASSERT_FALSE(latchkey_util::decodeSeedTable(nullptr, 0, out));
    TEST_ASSERT_EQUAL_UINT16(1999, out.year);
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_the_table_encodes_byte_for_byte);
    RUN_TEST(test_an_unconfirmed_table_says_so);
    RUN_TEST(test_the_table_survives_a_round_trip);
    RUN_TEST(test_damaged_blobs_are_refused_and_leave_the_output_alone);
    return UNITY_END();
}
