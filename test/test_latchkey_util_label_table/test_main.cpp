// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>
#include <string>
#include <vector>

#include "latchkey_util/label_table.h"

using latchkey_util::Label;
using latchkey_util::LabelTable;
using latchkey_util::WeeklyWindow;

void setUp() {}

void tearDown() {}

static Label label(uint64_t id, bool managed, const std::string& name) {
    Label entry;
    entry.id = id;
    entry.managed = managed;
    entry.name = name;
    return entry;
}

static std::vector<uint8_t> encoded(const LabelTable& table) { return table.encode(); }

static LabelTable decoded(const std::vector<uint8_t>& bytes) {
    LabelTable table;
    TEST_ASSERT_TRUE(LabelTable::decode(bytes.data(), bytes.size(), table));
    return table;
}

static void test_an_empty_table_encodes_its_version_and_no_entries() {
    const std::vector<uint8_t> bytes = encoded(LabelTable{});
    const std::vector<uint8_t> expected{0x01, 0x00};
    TEST_ASSERT_EQUAL_UINT(expected.size(), bytes.size());
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected.data(), bytes.data(), expected.size());
    TEST_ASSERT_EQUAL_UINT(0, decoded(bytes).size());
}

static void test_entries_encode_byte_for_byte() {
    LabelTable table;
    TEST_ASSERT_TRUE(table.put(label(0x0123456789abULL, true, "Guest")));
    Label card = label(3141592653ULL, false, "");
    card.cycle = WeeklyWindow{0x1F, 8 * 60, 18 * 60 + 30};
    TEST_ASSERT_TRUE(table.put(card));
    const std::vector<uint8_t> expected{
        0x01, 0x02,
        0x00, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x01, 0x05, 'G', 'u', 'e', 's', 't',
        0x00, 0x00, 0x00, 0x00, 0xbb, 0x40, 0xe6, 0x4d, 0x02, 0x00, 0x1f, 0x01, 0xe0, 0x04, 0x56,
    };
    const std::vector<uint8_t> bytes = encoded(table);
    TEST_ASSERT_EQUAL_UINT(expected.size(), bytes.size());
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected.data(), bytes.data(), expected.size());
}

static void test_a_table_survives_a_round_trip() {
    LabelTable table;
    TEST_ASSERT_TRUE(table.put(label(1, true, "Front porch \xc3\xa9")));
    Label cycled = label(281474976710655ULL, true, "");
    cycled.cycle = WeeklyWindow{0x60, 0, 1440};
    TEST_ASSERT_TRUE(table.put(cycled));
    TEST_ASSERT_TRUE(table.put(label(18446744073709551615ULL, false, std::string(48, 'x'))));
    const LabelTable copy = decoded(encoded(table));
    TEST_ASSERT_EQUAL_UINT(3, copy.size());
    const Label* first = copy.find(1);
    TEST_ASSERT_NOT_NULL(first);
    TEST_ASSERT_TRUE(first->managed);
    TEST_ASSERT_EQUAL_STRING("Front porch \xc3\xa9", first->name.c_str());
    TEST_ASSERT_FALSE(first->cycle.has_value());
    const Label* second = copy.find(281474976710655ULL);
    TEST_ASSERT_NOT_NULL(second);
    TEST_ASSERT_TRUE(second->cycle.has_value());
    TEST_ASSERT_EQUAL_UINT8(0x60, second->cycle->days);
    TEST_ASSERT_EQUAL_UINT16(0, second->cycle->startMinute);
    TEST_ASSERT_EQUAL_UINT16(1440, second->cycle->endMinute);
    const Label* third = copy.find(18446744073709551615ULL);
    TEST_ASSERT_NOT_NULL(third);
    TEST_ASSERT_FALSE(third->managed);
    TEST_ASSERT_EQUAL_UINT(48, third->name.size());
}

static void test_put_replaces_the_entry_with_the_same_id() {
    LabelTable table;
    TEST_ASSERT_TRUE(table.put(label(7, true, "Old")));
    TEST_ASSERT_TRUE(table.put(label(7, false, "New")));
    TEST_ASSERT_EQUAL_UINT(1, table.size());
    TEST_ASSERT_EQUAL_STRING("New", table.find(7)->name.c_str());
    TEST_ASSERT_FALSE(table.find(7)->managed);
}

static void test_an_entry_that_says_nothing_is_dropped() {
    LabelTable table;
    TEST_ASSERT_TRUE(table.put(label(7, true, "Kept")));
    TEST_ASSERT_TRUE(table.put(label(7, false, "")));
    TEST_ASSERT_EQUAL_UINT(0, table.size());
    TEST_ASSERT_NULL(table.find(7));
    TEST_ASSERT_TRUE(table.put(label(8, false, "")));
    TEST_ASSERT_EQUAL_UINT(0, table.size());
}

static void test_the_table_holds_at_most_32_entries() {
    TEST_ASSERT_EQUAL_UINT(32, latchkey_util::kMaxLabels);
    LabelTable table;
    for (uint64_t id = 1; id <= latchkey_util::kMaxLabels; ++id) {
        TEST_ASSERT_TRUE(table.hasRoomFor(id));
        TEST_ASSERT_TRUE(table.put(label(id, true, "")));
    }
    TEST_ASSERT_FALSE(table.hasRoomFor(99));
    TEST_ASSERT_FALSE(table.put(label(99, true, "")));
    TEST_ASSERT_EQUAL_UINT(32, table.size());
    TEST_ASSERT_TRUE(table.hasRoomFor(5));
    TEST_ASSERT_TRUE(table.put(label(5, true, "Renamed")));
    TEST_ASSERT_TRUE(table.remove(5));
    TEST_ASSERT_TRUE(table.hasRoomFor(99));
}

static void test_names_and_windows_outside_the_limits_are_refused() {
    LabelTable table;
    TEST_ASSERT_FALSE(table.put(label(1, true, std::string(49, 'x'))));
    Label cycled = label(2, true, "");
    cycled.cycle = WeeklyWindow{0x00, 60, 120};
    TEST_ASSERT_FALSE(table.put(cycled));
    cycled.cycle = WeeklyWindow{0x80, 60, 120};
    TEST_ASSERT_FALSE(table.put(cycled));
    cycled.cycle = WeeklyWindow{0x01, 120, 120};
    TEST_ASSERT_FALSE(table.put(cycled));
    cycled.cycle = WeeklyWindow{0x01, 60, 1441};
    TEST_ASSERT_FALSE(table.put(cycled));
    TEST_ASSERT_EQUAL_UINT(0, table.size());
}

static void test_remove_and_keep_only_report_whether_anything_changed() {
    LabelTable table;
    TEST_ASSERT_TRUE(table.put(label(1, true, "a")));
    TEST_ASSERT_TRUE(table.put(label(2, true, "b")));
    TEST_ASSERT_TRUE(table.put(label(3, true, "c")));
    TEST_ASSERT_FALSE(table.remove(9));
    TEST_ASSERT_TRUE(table.remove(2));
    TEST_ASSERT_FALSE(table.keepOnly({1, 3, 4}));
    TEST_ASSERT_TRUE(table.keepOnly({3}));
    TEST_ASSERT_EQUAL_UINT(1, table.size());
    TEST_ASSERT_NOT_NULL(table.find(3));
}

static void test_damaged_blobs_are_refused() {
    LabelTable table;
    TEST_ASSERT_TRUE(table.put(label(0x0123456789abULL, true, "Guest")));
    const std::vector<uint8_t> good = encoded(table);
    const std::vector<std::vector<uint8_t>> bad = {
        {},
        {0x01},
        {0x02, 0x00},
        {0x01, 0x01},
        {0x01, 0x21},
        {0x01, 0x00, 0x00},
        {0x01, 0x01, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0x31},
        {0x01, 0x01, 0, 0, 0, 0, 0, 0, 0, 1, 0x04, 0x00},
        {0x01, 0x01, 0, 0, 0, 0, 0, 0, 0, 1, 0x02, 0x00, 0x01, 0x00, 0x78, 0x00},
        {0x01, 0x01, 0, 0, 0, 0, 0, 0, 0, 1, 0x02, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x78},
        {0x01, 0x02, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0x00},
        {0x01, 0x01, 0, 0, 0, 0, 0, 0, 0, 1, 0x00, 0x00},
    };
    std::vector<uint8_t> truncated = good;
    truncated.pop_back();
    std::vector<uint8_t> trailed = good;
    trailed.push_back(0x00);
    std::vector<std::vector<uint8_t>> cases = bad;
    cases.push_back(truncated);
    cases.push_back(trailed);
    for (const std::vector<uint8_t>& bytes : cases) {
        LabelTable out;
        TEST_ASSERT_TRUE(out.put(label(42, true, "untouched")));
        TEST_ASSERT_FALSE(LabelTable::decode(bytes.data(), bytes.size(), out));
        TEST_ASSERT_EQUAL_UINT(1, out.size());
        TEST_ASSERT_NOT_NULL(out.find(42));
    }
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_an_empty_table_encodes_its_version_and_no_entries);
    RUN_TEST(test_entries_encode_byte_for_byte);
    RUN_TEST(test_a_table_survives_a_round_trip);
    RUN_TEST(test_put_replaces_the_entry_with_the_same_id);
    RUN_TEST(test_an_entry_that_says_nothing_is_dropped);
    RUN_TEST(test_the_table_holds_at_most_32_entries);
    RUN_TEST(test_names_and_windows_outside_the_limits_are_refused);
    RUN_TEST(test_remove_and_keep_only_report_whether_anything_changed);
    RUN_TEST(test_damaged_blobs_are_refused);
    return UNITY_END();
}
